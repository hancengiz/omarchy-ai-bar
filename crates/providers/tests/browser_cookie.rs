use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_providers::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    BrowserCookieImportError, ChromiumCookieDecryptionError, ChromiumCookieDecryptor,
    DisabledChromiumCookieDecryptor, MAX_BROWSER_COOKIE_BYTES, MAX_BROWSER_COOKIE_ROWS,
    import_browser_cookies, import_browser_cookies_merging_chromium_stores_with_decryptor,
    import_browser_cookies_with_decryptor,
};
use oab_providers::browser_profile::{
    BrowserKind, BrowserProfile, BrowserProfileDiscovery, BrowserProfileRoots,
};
use oab_providers::cookie::{
    CookieImport, CookieImportOrder, CookieJar, CookieSourceId, CookieUrlPolicy, ValidatedCookieUrl,
};
use oab_providers::sqlite_snapshot::SqliteSnapshotError;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const SOURCE: CookieSourceId = CookieSourceId::new(41);
const CHROMIUM_EPOCH_OFFSET_MICROSECONDS: i64 = 11_644_473_600_000_000;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-browser-cookie-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create fixture root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn directory(&self, relative: impl AsRef<Path>) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(&path).expect("create fixture directory");
        path
    }

    fn write(&self, relative: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(&path, bytes).expect("write fixture file");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn discovered_profile(fixture: &TestDirectory, browser: BrowserKind) -> BrowserProfile {
    fixture.directory("home");
    fixture.directory("home/config");
    match browser {
        BrowserKind::Chromium => {
            fixture.directory("home/config/chromium/Default");
        }
        BrowserKind::GoogleChrome => {
            fixture.directory("home/config/google-chrome/Default");
        }
        BrowserKind::Brave => {
            fixture.directory("home/config/BraveSoftware/Brave-Browser/Default");
        }
        BrowserKind::BraveOrigin => {
            fixture.directory("home/config/BraveSoftware/Brave-Origin/Default");
        }
        BrowserKind::MicrosoftEdge => {
            fixture.directory("home/config/microsoft-edge/Default");
        }
        BrowserKind::Firefox => {
            fixture.directory("home/.mozilla/firefox/Profiles/default");
            fixture.write(
                "home/.mozilla/firefox/profiles.ini",
                b"[Profile0]\nPath=Profiles/default\nIsRelative=1\nDefault=1\n",
            );
        }
        BrowserKind::Zen => {
            fixture.directory("home/.zen/Profiles/default");
            fixture.write(
                "home/.zen/profiles.ini",
                b"[Profile0]\nPath=Profiles/default\nIsRelative=1\nDefault=1\n",
            );
        }
    }
    let roots = BrowserProfileRoots::new(
        fixture.path().join("home"),
        fixture.path().join("home/config"),
        None::<&Path>,
    )
    .expect("fixture roots");
    BrowserProfileDiscovery::with_roots(roots)
        .discover()
        .profiles()
        .iter()
        .find(|profile| profile.browser() == browser)
        .expect("discovered fixture profile")
        .clone()
}

fn allowlist(rules: &[(&str, BrowserCookieDomainPolicy)]) -> BrowserCookieDomainAllowlist {
    BrowserCookieDomainAllowlist::new(rules.iter().map(|(domain, policy)| {
        BrowserCookieDomainRule {
            domain,
            policy: *policy,
        }
    }))
    .expect("valid fixture allowlist")
}

fn exact(domain: &str) -> BrowserCookieDomainAllowlist {
    allowlist(&[(domain, BrowserCookieDomainPolicy::Exact)])
}

fn domain_and_subdomains(domain: &str) -> BrowserCookieDomainAllowlist {
    allowlist(&[(domain, BrowserCookieDomainPolicy::DomainAndSubdomains)])
}

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
}

fn chromium_timestamp(timestamp: OffsetDateTime) -> i64 {
    timestamp
        .unix_timestamp()
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(i64::from(timestamp.nanosecond() / 1_000)))
        .and_then(|value| value.checked_add(CHROMIUM_EPOCH_OFFSET_MICROSECONDS))
        .expect("fixture Chromium timestamp")
}

fn chromium_cookie_schema(connection: &Connection) {
    connection
        .execute_batch(
            "CREATE TABLE cookies(
                host_key TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL,
                value TEXT NOT NULL,
                encrypted_value BLOB
             );",
        )
        .expect("create Chromium cookie schema");
}

fn chromium_schema(connection: &Connection, version: u32) {
    chromium_cookie_schema(connection);
    connection
        .execute_batch(
            "CREATE TABLE meta(
                key TEXT NOT NULL,
                value
             );",
        )
        .expect("create Chromium metadata schema");
    connection
        .execute(
            "INSERT INTO meta(key, value) VALUES ('version', ?1)",
            [version],
        )
        .expect("insert Chromium database version");
}

fn firefox_schema(connection: &Connection) {
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
        .expect("create Firefox cookie schema");
}

fn chromium_database(profile: &BrowserProfile, relative: &str, wal: bool) -> Connection {
    chromium_database_with_version(profile, relative, wal, 23)
}

fn chromium_database_with_version(
    profile: &BrowserProfile,
    relative: &str,
    wal: bool,
    version: u32,
) -> Connection {
    let path = profile.path().join(relative);
    fs::create_dir_all(path.parent().expect("database parent")).expect("create database parent");
    let connection = Connection::open(path).expect("open Chromium fixture database");
    if wal {
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .expect("enable WAL");
    }
    chromium_schema(&connection, version);
    connection
}

fn firefox_database(profile: &BrowserProfile, wal: bool) -> Connection {
    let connection =
        Connection::open(profile.path().join("cookies.sqlite")).expect("open Firefox database");
    if wal {
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .expect("enable WAL");
    }
    firefox_schema(&connection);
    connection
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture parameters mirror the fixed Chromium cookie schema"
)]
fn insert_chromium(
    connection: &Connection,
    host: &str,
    name: &str,
    path: &str,
    expires: i64,
    secure: i64,
    value: &str,
    encrypted: &[u8],
) {
    connection
        .execute(
            "INSERT INTO cookies(
                host_key, name, path, expires_utc, is_secure, value, encrypted_value
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![host, name, path, expires, secure, value, encrypted],
        )
        .expect("insert Chromium cookie");
}

fn insert_repeated_chromium(connection: &mut Connection, count: usize, name: &str, value: &str) {
    let transaction = connection.transaction().expect("repeated row transaction");
    {
        let mut statement = transaction
            .prepare(
                "INSERT INTO cookies(
                    host_key, name, path, expires_utc, is_secure, value, encrypted_value
                 ) VALUES ('example.com', ?1, '/', 0, 1, ?2, X'')",
            )
            .expect("repeated row statement");
        for _ in 0..count {
            statement
                .execute(params![name, value])
                .expect("insert repeated Chromium row");
        }
    }
    transaction.commit().expect("commit repeated rows");
}

fn insert_firefox(
    connection: &Connection,
    host: &str,
    name: &str,
    path: &str,
    expires: i64,
    secure: i64,
    value: &str,
) {
    connection
        .execute(
            "INSERT INTO moz_cookies(host, name, path, expiry, isSecure, value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![host, name, path, expires, secure, value],
        )
        .expect("insert Firefox cookie");
}

fn jar(import: CookieImport) -> CookieJar {
    let order = CookieImportOrder::new([SOURCE]).expect("source order");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn import_merged_chromium(
    profile: &BrowserProfile,
    allowlist: &BrowserCookieDomainAllowlist,
) -> Result<CookieImport, BrowserCookieImportError> {
    import_browser_cookies_merging_chromium_stores_with_decryptor(
        profile,
        SOURCE,
        allowlist,
        &DisabledChromiumCookieDecryptor,
    )
}

fn https(raw: &str) -> ValidatedCookieUrl {
    ValidatedCookieUrl::parse(raw, CookieUrlPolicy::HttpsOnly).expect("HTTPS fixture URL")
}

fn header(jar: &CookieJar, target: &ValidatedCookieUrl, at: OffsetDateTime) -> Option<String> {
    jar.header_for(target, at)
        .expect("select header")
        .map(|header| header.expose().to_owned())
}

#[test]
fn allowlists_are_bounded_canonical_and_redacted() {
    assert_eq!(
        BrowserCookieDomainAllowlist::new([]).expect_err("empty allowlist"),
        BrowserCookieImportError::InvalidAllowlist
    );
    for invalid in [
        ".example.com",
        "example.com.",
        "*.example.com",
        "example_com",
        "127.0.0.1",
        "[::1]",
        "com",
        "co.uk",
        "github.io",
        "canary.example.com\n.evil.test",
    ] {
        let error = BrowserCookieDomainAllowlist::new([BrowserCookieDomainRule {
            domain: invalid,
            policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
        }])
        .expect_err("invalid allowlist domain");
        assert_eq!(error, BrowserCookieImportError::InvalidAllowlist);
        assert!(!format!("{error:?} {error}").contains(invalid));
    }
    assert_eq!(
        BrowserCookieDomainAllowlist::new([
            BrowserCookieDomainRule {
                domain: "example.com",
                policy: BrowserCookieDomainPolicy::Exact,
            },
            BrowserCookieDomainRule {
                domain: "EXAMPLE.COM",
                policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
            },
        ])
        .expect_err("canonical duplicate"),
        BrowserCookieImportError::InvalidAllowlist
    );
    let excessive = (0..33)
        .map(|index| format!("host{index}.example.com"))
        .collect::<Vec<_>>();
    assert_eq!(
        BrowserCookieDomainAllowlist::new(excessive.iter().map(|domain| {
            BrowserCookieDomainRule {
                domain,
                policy: BrowserCookieDomainPolicy::Exact,
            }
        }))
        .expect_err("domain count bound"),
        BrowserCookieImportError::InvalidAllowlist
    );

    let idn = exact("BÜCHER.example");
    let rendered = format!(
        "{idn:?} {:?}",
        BrowserCookieDomainRule {
            domain: "private-canary.example",
            policy: BrowserCookieDomainPolicy::Exact,
        }
    );
    assert_eq!(idn.len(), 1);
    assert!(!idn.is_empty());
    assert!(!rendered.contains("xn--"));
    assert!(!rendered.contains("private-canary"));
    assert_eq!(exact("localhost").len(), 1);
    assert!(
        BrowserCookieDomainAllowlist::new([BrowserCookieDomainRule {
            domain: "localhost",
            policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
        }])
        .is_err()
    );
}

#[test]
fn firefox_reads_live_wal_and_preserves_domain_path_expiry_and_isolation() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Firefox);
    let writer = firefox_database(&profile, true);
    insert_firefox(
        &writer,
        ".example.com",
        "domain_session",
        "/api",
        (now() + Duration::HOUR).unix_timestamp(),
        1,
        "domain-value",
    );
    insert_firefox(
        &writer,
        "api.example.com",
        "host_session",
        "/",
        0,
        0,
        "host-value",
    );
    insert_firefox(
        &writer,
        "example.com.evil.test",
        "isolation_canary",
        "/",
        0,
        0,
        "must-not-import",
    );

    let imported = import_browser_cookies(&profile, SOURCE, &domain_and_subdomains("example.com"))
        .expect("Firefox WAL import");
    let jar = jar(imported);
    let request = https("https://api.example.com/api/usage");
    let active = header(&jar, &request, now()).expect("active Firefox cookies");
    assert_eq!(
        active,
        "domain_session=domain-value; host_session=host-value"
    );
    assert!(!active.contains("isolation_canary"));
    assert_eq!(
        header(&jar, &request, now() + Duration::hours(2)),
        Some("host_session=host-value".to_owned())
    );
    assert_eq!(
        header(&jar, &https("https://api.example.com/apix"), now()),
        Some("host_session=host-value".to_owned())
    );
}

#[test]
fn zen_uses_the_gecko_plaintext_schema_without_decryptor_calls() {
    struct RejectingDecryptor;
    impl ChromiumCookieDecryptor for RejectingDecryptor {
        fn decrypt(
            &self,
            _browser: BrowserKind,
            _encrypted_value: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, ChromiumCookieDecryptionError> {
            panic!("Gecko must not invoke Chromium decryption")
        }
    }

    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Zen);
    let database = firefox_database(&profile, false);
    insert_firefox(
        &database,
        "zen.example.com",
        "zen_session",
        "/",
        0,
        1,
        "zen-value",
    );
    let imported = import_browser_cookies_with_decryptor(
        &profile,
        SOURCE,
        &exact("zen.example.com"),
        &RejectingDecryptor,
    )
    .expect("Zen plaintext import");
    assert_eq!(
        header(&jar(imported), &https("https://zen.example.com/"), now()),
        Some("zen_session=zen-value".to_owned())
    );
}

#[test]
fn chromium_prefers_modern_live_wal_and_falls_back_only_when_modern_is_missing() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let modern = chromium_database(&profile, "Network/Cookies", true);
    insert_chromium(
        &modern,
        "example.com",
        "modern",
        "/",
        0,
        1,
        "modern-value",
        &[],
    );
    let legacy = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &legacy,
        "example.com",
        "legacy",
        "/",
        0,
        1,
        "legacy-value",
        &[],
    );
    let imported = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
        .expect("modern Chromium import");
    assert_eq!(
        header(&jar(imported), &https("https://example.com/"), now()),
        Some("modern=modern-value".to_owned())
    );

    let legacy_fixture = TestDirectory::new();
    let legacy_profile = discovered_profile(&legacy_fixture, BrowserKind::GoogleChrome);
    let legacy = chromium_database(&legacy_profile, "Cookies", false);
    insert_chromium(
        &legacy,
        "example.com",
        "legacy",
        "/",
        0,
        1,
        "legacy-value",
        &[],
    );
    let imported = import_browser_cookies(&legacy_profile, SOURCE, &exact("example.com"))
        .expect("legacy Chromium fallback");
    assert_eq!(
        header(&jar(imported), &https("https://example.com/"), now()),
        Some("legacy=legacy-value".to_owned())
    );
}

#[test]
fn opt_in_chromium_merge_finds_primary_cookie_when_modern_store_lacks_it() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let modern = chromium_database(&profile, "Network/Cookies", false);
    insert_chromium(
        &modern,
        "example.com",
        "unrelated",
        "/",
        0,
        1,
        "modern-value",
        &[],
    );
    let primary = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &primary,
        "example.com",
        "kimi-auth",
        "/",
        0,
        1,
        "primary-token",
        &[],
    );
    drop((modern, primary));

    let ordinary = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
        .expect("ordinary modern-preferred import");
    assert_eq!(
        header(&jar(ordinary), &https("https://example.com/"), now()),
        Some("unrelated=modern-value".to_owned())
    );

    let merged = import_merged_chromium(&profile, &exact("example.com"))
        .expect("opt-in merged Chromium import");
    let merged_header =
        header(&jar(merged), &https("https://example.com/"), now()).expect("merged cookies");
    assert!(merged_header.contains("kimi-auth=primary-token"));
    assert!(merged_header.contains("unrelated=modern-value"));
}

#[test]
fn opt_in_chromium_merge_prefers_later_expiry_and_network_on_ties() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let modern = chromium_database(&profile, "Network/Cookies", false);
    let primary = chromium_database(&profile, "Cookies", false);
    let first_expiry = chromium_timestamp(now() + Duration::HOUR);
    let later_expiry = chromium_timestamp(now() + Duration::hours(2));
    let equal_expiry = chromium_timestamp(now() + Duration::hours(3));

    for (name, expiry, value) in [
        ("later", first_expiry, "network-earlier"),
        ("equal", equal_expiry, "network-equal"),
        ("session", 0, "network-session"),
        ("network_persistent", first_expiry, "network-persistent"),
        ("primary_persistent", 0, "network-session-loses"),
    ] {
        insert_chromium(&modern, "example.com", name, "/", expiry, 1, value, &[]);
    }
    for (name, expiry, value) in [
        ("later", later_expiry, "primary-later"),
        ("equal", equal_expiry, "primary-equal-loses"),
        ("session", 0, "primary-session-loses"),
        ("network_persistent", 0, "primary-session-loses"),
        ("primary_persistent", first_expiry, "primary-persistent"),
    ] {
        insert_chromium(&primary, "example.com", name, "/", expiry, 1, value, &[]);
    }
    drop((modern, primary));

    let merged = import_merged_chromium(&profile, &exact("example.com"))
        .expect("precedence-aware merged import");
    let merged_header =
        header(&jar(merged), &https("https://example.com/"), now()).expect("merged cookies");
    for selected in [
        "later=primary-later",
        "equal=network-equal",
        "session=network-session",
        "network_persistent=network-persistent",
        "primary_persistent=primary-persistent",
    ] {
        assert!(merged_header.contains(selected), "missing {selected}");
    }
    for rejected in [
        "network-earlier",
        "primary-equal-loses",
        "primary-session-loses",
        "network-session-loses",
    ] {
        assert!(!merged_header.contains(rejected), "retained {rejected}");
    }
}

#[test]
fn every_supported_chromium_layout_uses_the_same_bounded_schema() {
    for (index, browser) in [
        BrowserKind::Chromium,
        BrowserKind::GoogleChrome,
        BrowserKind::Brave,
        BrowserKind::BraveOrigin,
        BrowserKind::MicrosoftEdge,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, browser);
        let database = chromium_database(&profile, "Cookies", false);
        let value = format!("browser-{index}");
        insert_chromium(&database, "example.com", "session", "/", 0, 1, &value, &[]);
        let imported = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
            .expect("Chromium-family import");
        assert_eq!(
            header(&jar(imported), &https("https://example.com/"), now()),
            Some(format!("session={value}"))
        );
    }
}

#[test]
fn exact_and_subdomain_policies_are_enforced_in_sql_and_after_decode() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let database = chromium_database(&profile, "Cookies", false);
    for (host, name) in [
        ("example.com", "exact_host"),
        (".example.com", "exact_domain"),
        ("api.example.com", "subdomain"),
        ("evil-example.com", "boundary_canary"),
        ("example.com.evil.test", "suffix_canary"),
    ] {
        insert_chromium(&database, host, name, "/", 0, 1, name, &[]);
    }

    let exact_import =
        import_browser_cookies(&profile, SOURCE, &exact("example.com")).expect("exact import");
    let exact_header =
        header(&jar(exact_import), &https("https://example.com/"), now()).expect("exact cookies");
    assert!(exact_header.contains("exact_host=exact_host"));
    assert!(exact_header.contains("exact_domain=exact_domain"));
    assert!(!exact_header.contains("subdomain"));
    assert!(!exact_header.contains("canary"));

    let domain_import =
        import_browser_cookies(&profile, SOURCE, &domain_and_subdomains("example.com"))
            .expect("domain import");
    let domain_header = header(
        &jar(domain_import),
        &https("https://api.example.com/"),
        now(),
    )
    .expect("domain cookies");
    assert!(domain_header.contains("exact_domain=exact_domain"));
    assert!(domain_header.contains("subdomain=subdomain"));
    assert!(!domain_header.contains("boundary_canary"));
    assert!(!domain_header.contains("suffix_canary"));
}

#[test]
fn idn_allowlists_match_only_their_canonical_ascii_host() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let database = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &database,
        "xn--bcher-kva.example",
        "idn_session",
        "/",
        0,
        1,
        "idn-value",
        &[],
    );
    insert_chromium(
        &database,
        "xn--bcher-kva.example.evil.test",
        "idn_boundary_canary",
        "/",
        0,
        1,
        "must-not-import",
        &[],
    );

    let imported = import_browser_cookies(&profile, SOURCE, &exact("BÜCHER.example"))
        .expect("canonical IDN import");
    assert_eq!(
        header(
            &jar(imported),
            &https("https://xn--bcher-kva.example/"),
            now()
        ),
        Some("idn_session=idn-value".to_owned())
    );
}

struct FixtureDecryptor;

impl ChromiumCookieDecryptor for FixtureDecryptor {
    fn decrypt(
        &self,
        browser: BrowserKind,
        encrypted_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChromiumCookieDecryptionError> {
        assert_eq!(browser, BrowserKind::Chromium);
        match encrypted_value {
            b"fixture-ciphertext" => Ok(Zeroizing::new(b"decrypted-value".to_vec())),
            b"unavailable" => Err(ChromiumCookieDecryptionError::Unavailable),
            _ => Err(ChromiumCookieDecryptionError::Failed),
        }
    }
}

struct RawValueDecryptor {
    plaintext: Vec<u8>,
}

impl ChromiumCookieDecryptor for RawValueDecryptor {
    fn decrypt(
        &self,
        browser: BrowserKind,
        encrypted_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChromiumCookieDecryptionError> {
        assert_eq!(browser, BrowserKind::Chromium);
        assert_eq!(encrypted_value, b"fixture-ciphertext");
        Ok(Zeroizing::new(self.plaintext.clone()))
    }
}

fn import_encrypted_fixture(
    database_version: u32,
    raw_host: &str,
    plaintext: Vec<u8>,
) -> Result<CookieImport, BrowserCookieImportError> {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let database = chromium_database_with_version(&profile, "Cookies", false, database_version);
    insert_chromium(
        &database,
        raw_host,
        "encrypted",
        "/",
        0,
        1,
        "",
        b"fixture-ciphertext",
    );
    import_browser_cookies_with_decryptor(
        &profile,
        SOURCE,
        &domain_and_subdomains("example.com"),
        &RawValueDecryptor { plaintext },
    )
}

#[test]
fn chromium_v23_uses_raw_decrypted_value_without_a_host_digest() {
    let imported = import_encrypted_fixture(23, "example.com", b"v23-value".to_vec())
        .expect("v23 decrypted import");
    assert_eq!(
        header(&jar(imported), &https("https://example.com/"), now()),
        Some("encrypted=v23-value".to_owned())
    );
}

#[test]
fn chromium_v24_verifies_and_strips_the_exact_raw_host_digest() {
    let raw_host = ".example.com";
    let mut plaintext = Sha256::digest(raw_host.as_bytes()).to_vec();
    plaintext.extend_from_slice(b"v24-value");
    let imported =
        import_encrypted_fixture(24, raw_host, plaintext).expect("v24 host-bound import");
    assert_eq!(
        header(&jar(imported), &https("https://api.example.com/"), now()),
        Some("encrypted=v24-value".to_owned())
    );
}

#[test]
fn chromium_v24_rejects_wrong_host_and_truncated_digests() {
    let mut wrong_host = Sha256::digest(b"other.example.com").to_vec();
    wrong_host.extend_from_slice(b"wrong-host-canary");
    for plaintext in [wrong_host, vec![7; 31]] {
        let error = import_encrypted_fixture(24, "example.com", plaintext)
            .expect_err("invalid v24 host digest");
        assert_eq!(error, BrowserCookieImportError::DecryptionFailed);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("wrong-host"));
        assert!(!rendered.contains("example.com"));
    }
}

#[test]
fn encrypted_rows_report_unavailable_but_plaintext_can_continue() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let database = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &database,
        "example.com",
        "encrypted",
        "/",
        0,
        1,
        "",
        b"fixture-ciphertext",
    );
    assert_eq!(
        import_browser_cookies(&profile, SOURCE, &exact("example.com"))
            .expect_err("disabled decryption"),
        BrowserCookieImportError::EncryptedCookiesUnavailable
    );

    insert_chromium(
        &database,
        "example.com",
        "plaintext",
        "/",
        0,
        1,
        "plain-value",
        &[],
    );
    let mixed = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
        .expect("plaintext survives unavailable encryption");
    assert_eq!(
        header(&jar(mixed), &https("https://example.com/"), now()),
        Some("plaintext=plain-value".to_owned())
    );

    let decrypted = import_browser_cookies_with_decryptor(
        &profile,
        SOURCE,
        &exact("example.com"),
        &FixtureDecryptor,
    )
    .expect("fixture decryption");
    let decrypted_header =
        header(&jar(decrypted), &https("https://example.com/"), now()).expect("decrypted cookies");
    assert!(decrypted_header.contains("encrypted=decrypted-value"));
    assert!(decrypted_header.contains("plaintext=plain-value"));
}

#[test]
fn attempted_invalid_decryption_fails_stably() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let database = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &database,
        "example.com",
        "encrypted",
        "/",
        0,
        1,
        "",
        b"invalid-ciphertext-canary",
    );
    let error = import_browser_cookies_with_decryptor(
        &profile,
        SOURCE,
        &exact("example.com"),
        &FixtureDecryptor,
    )
    .expect_err("invalid encrypted value");
    assert_eq!(error, BrowserCookieImportError::DecryptionFailed);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("ciphertext"));
    assert!(!rendered.contains("canary"));
}

#[test]
fn chromium_epoch_path_and_secure_flags_project_through_the_shared_jar() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let database = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &database,
        "localhost",
        "insecure",
        "/",
        0,
        0,
        "visible-http",
        &[],
    );
    insert_chromium(
        &database,
        "localhost",
        "secure",
        "/private",
        chromium_timestamp(now() + Duration::HOUR),
        1,
        "https-only",
        &[],
    );
    insert_chromium(
        &database,
        "localhost",
        "expired",
        "/",
        chromium_timestamp(now() - Duration::SECOND),
        0,
        "stale",
        &[],
    );
    let imported = import_browser_cookies(&profile, SOURCE, &exact("localhost"))
        .expect("loopback fixture import");
    let jar = jar(imported);
    let http = ValidatedCookieUrl::parse(
        "http://localhost:3000/private/usage",
        CookieUrlPolicy::LoopbackHttp,
    )
    .expect("typed loopback HTTP");
    assert_eq!(
        header(&jar, &http, now()),
        Some("insecure=visible-http".to_owned())
    );
    assert_eq!(
        header(&jar, &https("https://localhost/private/usage"), now()),
        Some("secure=https-only; insecure=visible-http".to_owned())
    );
    assert_eq!(
        header(&jar, &https("https://localhost/privatex"), now()),
        Some("insecure=visible-http".to_owned())
    );
}

#[test]
fn chromium_meta_version_is_exact_bounded_and_future_versions_fail_closed() {
    let cases = [
        ("", BrowserCookieImportError::MalformedSchema),
        (
            "CREATE TABLE meta(key TEXT NOT NULL, value);",
            BrowserCookieImportError::MalformedSchema,
        ),
        (
            "CREATE TABLE meta(key TEXT NOT NULL, value);
             INSERT INTO meta VALUES ('version', 23);
             INSERT INTO meta VALUES ('version', 24);",
            BrowserCookieImportError::MalformedData,
        ),
        (
            "CREATE TABLE meta(key TEXT NOT NULL, value);
             INSERT INTO meta VALUES ('version', 'meta-version-canary');",
            BrowserCookieImportError::MalformedData,
        ),
        (
            "CREATE TABLE meta(key TEXT NOT NULL, value);
             INSERT INTO meta VALUES ('version', '12345678901');",
            BrowserCookieImportError::MalformedData,
        ),
        (
            "CREATE TABLE meta(key TEXT NOT NULL, value);
             INSERT INTO meta VALUES ('version', X'18');",
            BrowserCookieImportError::MalformedData,
        ),
        (
            "CREATE TABLE meta(key TEXT NOT NULL, value);
             INSERT INTO meta VALUES ('version', 25);",
            BrowserCookieImportError::MalformedSchema,
        ),
    ];

    for (setup, expected) in cases {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let database = Connection::open(profile.path().join("Cookies"))
            .expect("open metadata fixture database");
        chromium_cookie_schema(&database);
        if !setup.is_empty() {
            database
                .execute_batch(setup)
                .expect("configure metadata fixture");
        }
        let error = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
            .expect_err("malformed or unsupported metadata");
        assert_eq!(error, expected, "metadata setup must fail closed");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("meta-version-canary"));
    }
}

#[test]
fn malformed_schema_types_timestamps_and_oversized_fields_fail_closed() {
    {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let path = profile.path().join("Cookies");
        let database = Connection::open(path).expect("malformed schema database");
        database
            .execute_batch("CREATE TABLE cookies(host_key TEXT, name TEXT);")
            .expect("malformed schema");
        database
            .execute_batch(
                "CREATE TABLE meta(key TEXT NOT NULL, value);
                 INSERT INTO meta(key, value) VALUES ('version', 23);",
            )
            .expect("valid metadata for malformed cookie schema");
        assert_eq!(
            import_browser_cookies(&profile, SOURCE, &exact("example.com"))
                .expect_err("missing columns"),
            BrowserCookieImportError::MalformedSchema
        );
    }

    for mutation in ["type", "timestamp", "value", "encrypted", "both"] {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let database = chromium_database(&profile, "Cookies", false);
        match mutation {
            "type" => {
                database
                    .execute(
                        "INSERT INTO cookies VALUES(
                            'example.com', X'37', '/', 0, 1, 'value', X''
                         )",
                        [],
                    )
                    .expect("wrong-type row");
            }
            "timestamp" => insert_chromium(
                &database,
                "example.com",
                "session",
                "/",
                -1,
                1,
                "value",
                &[],
            ),
            "value" => insert_chromium(
                &database,
                "example.com",
                "session",
                "/",
                0,
                1,
                &"x".repeat(16 * 1024 + 1),
                &[],
            ),
            "encrypted" => insert_chromium(
                &database,
                "example.com",
                "session",
                "/",
                0,
                1,
                "",
                &vec![7; 64 * 1024 + 1],
            ),
            "both" => insert_chromium(
                &database,
                "example.com",
                "session",
                "/",
                0,
                1,
                "plaintext-canary",
                b"encrypted-canary",
            ),
            _ => unreachable!(),
        }
        let error = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
            .expect_err("malformed row");
        let expected = if matches!(mutation, "value" | "encrypted") {
            BrowserCookieImportError::OversizedField
        } else {
            BrowserCookieImportError::MalformedData
        };
        assert_eq!(error, expected, "mutation {mutation}");
    }
}

#[test]
fn firefox_rejects_out_of_range_expiry() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Firefox);
    let database = firefox_database(&profile, false);
    insert_firefox(
        &database,
        "example.com",
        "session",
        "/",
        i64::MAX,
        1,
        "value",
    );
    assert_eq!(
        import_browser_cookies(&profile, SOURCE, &exact("example.com"))
            .expect_err("invalid Firefox timestamp"),
        BrowserCookieImportError::MalformedData
    );
}

#[test]
fn query_row_limit_is_enforced_with_limit_plus_one() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let mut database = chromium_database(&profile, "Cookies", false);
    let transaction = database.transaction().expect("row-cap transaction");
    {
        let mut statement = transaction
            .prepare(
                "INSERT INTO cookies(
                    host_key, name, path, expires_utc, is_secure, value, encrypted_value
                 ) VALUES ('example.com', ?1, '/', 0, 1, 'value', X'')",
            )
            .expect("row-cap statement");
        for index in 0..=MAX_BROWSER_COOKIE_ROWS {
            statement
                .execute([format!("cookie{index}")])
                .expect("insert bounded row");
        }
    }
    transaction.commit().expect("commit row-cap fixture");

    assert_eq!(
        import_browser_cookies(&profile, SOURCE, &exact("example.com")).expect_err("row limit"),
        BrowserCookieImportError::TooManyRows
    );
}

#[test]
fn opt_in_chromium_merge_enforces_aggregate_row_and_byte_limits() {
    {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let mut modern = chromium_database(&profile, "Network/Cookies", false);
        let mut primary = chromium_database(&profile, "Cookies", false);
        let modern_rows = MAX_BROWSER_COOKIE_ROWS / 2;
        insert_repeated_chromium(&mut modern, modern_rows, "duplicate", "value");
        insert_repeated_chromium(
            &mut primary,
            MAX_BROWSER_COOKIE_ROWS - modern_rows + 1,
            "duplicate",
            "value",
        );
        drop((modern, primary));

        assert_eq!(
            import_merged_chromium(&profile, &exact("example.com"))
                .expect_err("aggregate row limit"),
            BrowserCookieImportError::TooManyRows
        );
    }

    {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let mut modern = chromium_database(&profile, "Network/Cookies", false);
        let mut primary = chromium_database(&profile, "Cookies", false);
        let value = "x".repeat(16 * 1024);
        let rows = MAX_BROWSER_COOKIE_BYTES / value.len() + 1;
        let modern_rows = rows / 2;
        insert_repeated_chromium(&mut modern, modern_rows, "duplicate", &value);
        insert_repeated_chromium(&mut primary, rows - modern_rows, "duplicate", &value);
        drop((modern, primary));

        assert_eq!(
            import_merged_chromium(&profile, &exact("example.com"))
                .expect_err("aggregate byte limit"),
            BrowserCookieImportError::TooManyBytes
        );
    }
}

#[test]
fn opt_in_chromium_merge_fails_closed_on_unsafe_or_malformed_present_store() {
    {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let modern = chromium_database(&profile, "Network/Cookies", false);
        insert_chromium(
            &modern,
            "example.com",
            "modern",
            "/",
            0,
            1,
            "modern-value",
            &[],
        );
        drop(modern);
        let outside = fixture.path().join("private-primary-canary.sqlite");
        let outside_database = Connection::open(&outside).expect("outside primary database");
        chromium_schema(&outside_database, 23);
        drop(outside_database);
        std::os::unix::fs::symlink(&outside, profile.path().join("Cookies"))
            .expect("unsafe primary symlink");

        let error = import_merged_chromium(&profile, &exact("example.com"))
            .expect_err("unsafe present primary store");
        assert_eq!(
            error,
            BrowserCookieImportError::Snapshot(SqliteSnapshotError::UnsafeFile)
        );
        let rendered = format!("{error:?} {error} {profile:?}");
        assert!(!rendered.contains("private-primary-canary"));
        assert!(!rendered.contains(fixture.path().to_string_lossy().as_ref()));
    }

    {
        let fixture = TestDirectory::new();
        let profile = discovered_profile(&fixture, BrowserKind::Chromium);
        let modern = chromium_database(&profile, "Network/Cookies", false);
        insert_chromium(
            &modern,
            "example.com",
            "modern",
            "/",
            0,
            1,
            "modern-value",
            &[],
        );
        drop(modern);
        let malformed =
            Connection::open(profile.path().join("Cookies")).expect("malformed primary database");
        malformed
            .execute_batch(
                "CREATE TABLE cookies(host_key TEXT);
                 CREATE TABLE meta(key TEXT NOT NULL, value);
                 INSERT INTO meta(key, value) VALUES ('version', 23);",
            )
            .expect("malformed primary schema");
        drop(malformed);

        assert_eq!(
            import_merged_chromium(&profile, &exact("example.com"))
                .expect_err("malformed present primary store"),
            BrowserCookieImportError::MalformedSchema
        );
    }
}

#[test]
fn unsafe_modern_database_never_falls_back_to_legacy_and_errors_redact_paths() {
    let fixture = TestDirectory::new();
    let profile = discovered_profile(&fixture, BrowserKind::Chromium);
    let legacy = chromium_database(&profile, "Cookies", false);
    insert_chromium(
        &legacy,
        "example.com",
        "legacy",
        "/",
        0,
        1,
        "must-not-fallback",
        &[],
    );
    let outside = fixture.path().join("private-profile-canary.sqlite");
    let outside_database = Connection::open(&outside).expect("outside database");
    chromium_schema(&outside_database, 23);
    fs::create_dir_all(profile.path().join("Network")).expect("Network directory");
    std::os::unix::fs::symlink(&outside, profile.path().join("Network/Cookies"))
        .expect("unsafe modern symlink");

    let error = import_browser_cookies(&profile, SOURCE, &exact("example.com"))
        .expect_err("unsafe modern database");
    assert_eq!(
        error,
        BrowserCookieImportError::Snapshot(SqliteSnapshotError::UnsafeFile)
    );
    let rendered = format!("{error:?} {error} {profile:?}");
    assert!(!rendered.contains("private-profile-canary"));
    assert!(!rendered.contains(fixture.path().to_string_lossy().as_ref()));
}
