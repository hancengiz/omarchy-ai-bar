//! Bounded, profile-scoped Linux browser cookie database import.
//!
//! Each call reads exactly one validated browser profile through a short-lived
//! read-only SQLite snapshot and produces exactly one [`CookieImport`]. Browser
//! profile discovery, source ordering, key retrieval, and provider requests
//! remain explicit responsibilities of the caller.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::{self, Debug, Formatter};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use url::Host;
use zeroize::Zeroizing;

use crate::browser_profile::{BrowserKind, BrowserProfile};
use crate::cookie::{
    CookieDomainKind, CookieError, CookieImport, CookieRecord, CookieRecordSpec, CookieSourceId,
    MAX_COOKIE_JAR_BYTES, MAX_COOKIES_PER_IMPORT,
};
use crate::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};

const MAX_ALLOWLIST_DOMAINS: usize = 32;
const MAX_ALLOWLIST_DOMAIN_INPUT_BYTES: usize = 1_024;
const MAX_CANONICAL_DOMAIN_BYTES: usize = 253;
const MAX_COOKIE_HOST_BYTES: usize = 1_024;
const MAX_COOKIE_NAME_BYTES: usize = 256;
const MAX_COOKIE_PATH_BYTES: usize = 4 * 1024;
const MAX_COOKIE_VALUE_BYTES: usize = 16 * 1024;
const MAX_ENCRYPTED_VALUE_BYTES: usize = 64 * 1024;
const MAX_CHROMIUM_META_VERSION_BYTES: usize = 10;
const MAX_SUPPORTED_CHROMIUM_DATABASE_VERSION: u32 = 24;
const CHROMIUM_HOST_DIGEST_BYTES: usize = 32;
const CHROMIUM_TO_UNIX_EPOCH_MICROSECONDS: i64 = 11_644_473_600_000_000;
const MICROSECONDS_PER_SECOND: i64 = 1_000_000;

/// Maximum rows one profile import may inspect.
pub const MAX_BROWSER_COOKIE_ROWS: usize = MAX_COOKIES_PER_IMPORT;

/// Maximum aggregate SQLite field bytes an opt-in multi-store import may inspect.
pub const MAX_BROWSER_COOKIE_BYTES: usize = MAX_COOKIE_JAR_BYTES;

/// Host selection policy for one provider-owned allowlist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BrowserCookieDomainPolicy {
    /// Select only the exact canonical host/domain.
    Exact,
    /// Select the canonical domain and dot-delimited subdomains.
    DomainAndSubdomains,
}

/// Borrowed provider domain rule used to construct a validated allowlist.
#[derive(Clone, Copy)]
pub struct BrowserCookieDomainRule<'a> {
    /// Provider-owned DNS domain. Unicode input is canonicalized to IDNA ASCII.
    pub domain: &'a str,
    /// Exact-host or domain-and-subdomain matching.
    pub policy: BrowserCookieDomainPolicy,
}

impl Debug for BrowserCookieDomainRule<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserCookieDomainRule(<redacted>)")
    }
}

/// Validated, bounded provider domain allowlist.
pub struct BrowserCookieDomainAllowlist {
    rules: Vec<CanonicalDomainRule>,
}

impl BrowserCookieDomainAllowlist {
    /// Canonicalizes a non-empty list of unique provider DNS domains.
    ///
    /// `localhost` is accepted only with [`BrowserCookieDomainPolicy::Exact`]
    /// for explicitly typed development requests. IP literals, public-suffix-
    /// style entries, controls, wildcards, and duplicate domains are rejected.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted error when a rule is invalid or the fixed
    /// domain-count bound is exceeded.
    pub fn new<'a>(
        rules: impl IntoIterator<Item = BrowserCookieDomainRule<'a>>,
    ) -> Result<Self, BrowserCookieImportError> {
        let mut canonical = Vec::<CanonicalDomainRule>::new();
        for rule in rules {
            if canonical.len() >= MAX_ALLOWLIST_DOMAINS {
                return Err(BrowserCookieImportError::InvalidAllowlist);
            }
            let domain = canonical_allowlist_domain(rule.domain, rule.policy)?;
            if canonical
                .iter()
                .any(|existing| existing.domain.as_str() == domain.as_str())
            {
                return Err(BrowserCookieImportError::InvalidAllowlist);
            }
            canonical.push(CanonicalDomainRule {
                domain,
                policy: rule.policy,
            });
        }
        if canonical.is_empty() {
            return Err(BrowserCookieImportError::InvalidAllowlist);
        }
        canonical.sort_by(|left, right| {
            left.domain
                .as_bytes()
                .cmp(right.domain.as_bytes())
                .then_with(|| left.policy.cmp(&right.policy))
        });
        Ok(Self { rules: canonical })
    }

    /// Number of exact provider rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the allowlist has no rules. Valid instances are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn matches(&self, domain: &str) -> bool {
        self.rules.iter().any(|rule| match rule.policy {
            BrowserCookieDomainPolicy::Exact => domain == rule.domain.as_str(),
            BrowserCookieDomainPolicy::DomainAndSubdomains => {
                domain == rule.domain.as_str()
                    || domain
                        .strip_suffix(rule.domain.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        })
    }
}

impl Debug for BrowserCookieDomainAllowlist {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserCookieDomainAllowlist")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

/// Stable failures returned by an injected Chromium decryptor.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChromiumCookieDecryptionError {
    /// No decryption key or service is available for this profile.
    #[error("Chromium cookie decryption is unavailable")]
    Unavailable,
    /// The configured decryptor could not authenticate or decode the value.
    #[error("Chromium cookie decryption failed")]
    Failed,
}

/// Injected seam for a caller-owned Chromium cookie decryption backend.
pub trait ChromiumCookieDecryptor: Send + Sync {
    /// Decrypts one already-bounded `encrypted_value` blob.
    ///
    /// Implementations return raw decrypted bytes, including Chromium's v24+
    /// host-digest prefix. They must never log either input or output and
    /// should allocate secrets in [`Zeroizing`]. Host-digest verification and
    /// UTF-8 conversion remain importer-owned.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when no key is configured and `Failed` for an
    /// attempted but invalid ciphertext.
    fn decrypt(
        &self,
        browser: BrowserKind,
        encrypted_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChromiumCookieDecryptionError>;
}

/// Default decryptor that performs no keyring or browser-key access.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledChromiumCookieDecryptor;

impl ChromiumCookieDecryptor for DisabledChromiumCookieDecryptor {
    fn decrypt(
        &self,
        _browser: BrowserKind,
        _encrypted_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChromiumCookieDecryptionError> {
        Err(ChromiumCookieDecryptionError::Unavailable)
    }
}

/// Stable path- and cookie-free browser import failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BrowserCookieImportError {
    /// The provider domain allowlist was invalid or excessive.
    #[error("browser cookie domain allowlist is invalid")]
    InvalidAllowlist,
    /// Snapshot acquisition rejected or could not open the browser database.
    #[error("browser cookie database snapshot is unavailable")]
    Snapshot(#[source] SqliteSnapshotError),
    /// The expected fixed browser table/columns could not be queried.
    #[error("browser cookie database schema is unsupported")]
    MalformedSchema,
    /// A relevant row used an invalid SQLite type, host, timestamp, or value.
    #[error("browser cookie database contains malformed data")]
    MalformedData,
    /// A relevant text or encrypted field exceeded its fixed byte ceiling.
    #[error("browser cookie database field exceeds its size bound")]
    OversizedField,
    /// The fixed query returned more rows than one import may retain.
    #[error("browser cookie database row limit exceeded")]
    TooManyRows,
    /// Selected rows across an opt-in multi-store import exceeded the aggregate byte ceiling.
    #[error("browser cookie database byte limit exceeded")]
    TooManyBytes,
    /// Relevant encrypted rows existed but no usable cookie could be read
    /// without a configured Chromium key backend.
    #[error("encrypted Chromium cookies are unavailable")]
    EncryptedCookiesUnavailable,
    /// An injected decryptor attempted and failed to decode a relevant row.
    #[error("Chromium cookie decryption failed")]
    DecryptionFailed,
    /// A database row failed the shared cookie security boundary.
    #[error("browser cookie record is invalid")]
    Cookie(#[source] CookieError),
}

/// Imports cookies from one profile with Chromium decryption disabled.
///
/// # Errors
///
/// Returns a stable redacted snapshot, schema, data, size, encryption, or
/// shared-cookie validation error.
pub fn import_browser_cookies(
    profile: &BrowserProfile,
    source: CookieSourceId,
    allowlist: &BrowserCookieDomainAllowlist,
) -> Result<CookieImport, BrowserCookieImportError> {
    import_browser_cookies_with_decryptor(
        profile,
        source,
        allowlist,
        &DisabledChromiumCookieDecryptor,
    )
}

/// Imports cookies from one profile using an explicit Chromium decryptor.
///
/// Firefox and Zen values are plaintext and never invoke `decryptor`.
/// Chromium rows must contain at most one of `value` and `encrypted_value`;
/// rows containing both are rejected as malformed. Relevant encrypted rows
/// that report `Unavailable` are ignored when another usable row exists, but
/// return `EncryptedCookiesUnavailable` when none do.
///
/// # Errors
///
/// Returns a stable redacted snapshot, schema, data, size, encryption, or
/// shared-cookie validation error.
pub fn import_browser_cookies_with_decryptor(
    profile: &BrowserProfile,
    source: CookieSourceId,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<CookieImport, BrowserCookieImportError> {
    match profile.browser() {
        BrowserKind::Firefox | BrowserKind::Zen => import_gecko(profile, source, allowlist),
        BrowserKind::Chromium
        | BrowserKind::GoogleChrome
        | BrowserKind::Brave
        | BrowserKind::BraveOrigin
        | BrowserKind::MicrosoftEdge => import_chromium(profile, source, allowlist, decryptor),
    }
}

/// Imports one profile while opting Chromium into safe modern/primary store merging.
///
/// Firefox and Zen retain the ordinary single-store behavior. Chromium-family
/// profiles read every present `Network/Cookies` and root `Cookies` store. A
/// missing store is ignored, but any unsafe, malformed, or unsupported present
/// store fails the whole import closed. Selected rows share the same aggregate
/// record and byte ceilings as one ordinary cookie import.
///
/// Records are merged by name, canonical domain semantics, and path. A later
/// persistent expiry wins; the modern Network store wins equal expiries and
/// ties between two session cookies.
///
/// # Errors
///
/// Returns a stable redacted snapshot, schema, data, size, encryption, or
/// shared-cookie validation error.
pub fn import_browser_cookies_merging_chromium_stores_with_decryptor(
    profile: &BrowserProfile,
    source: CookieSourceId,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<CookieImport, BrowserCookieImportError> {
    match profile.browser() {
        BrowserKind::Firefox | BrowserKind::Zen => import_gecko(profile, source, allowlist),
        BrowserKind::Chromium
        | BrowserKind::GoogleChrome
        | BrowserKind::Brave
        | BrowserKind::BraveOrigin
        | BrowserKind::MicrosoftEdge => {
            import_merged_chromium(profile, source, allowlist, decryptor)
        }
    }
}

/// Imports each validated browser cookie store in provider-selection order.
///
/// Firefox and Zen return one store. Chromium-family profiles return each
/// present store separately in `Network/Cookies`, root `Cookies` order. Both
/// Chromium stores are fully read before this function returns, under one
/// aggregate row/byte budget, so an unsafe or malformed lower-priority store
/// still fails the whole import closed. `store_sources[0]` identifies Network
/// (or Gecko) and `store_sources[1]` identifies root Cookies. Callers retain the
/// imports as separate candidates and select the first store with an applicable
/// provider credential; they must not merge the records across stores.
///
/// # Errors
///
/// Returns a stable redacted snapshot, schema, data, size, encryption, or
/// shared-cookie validation error.
pub fn import_browser_cookie_stores_with_decryptor(
    profile: &BrowserProfile,
    store_sources: [CookieSourceId; 2],
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<Vec<CookieImport>, BrowserCookieImportError> {
    if store_sources[0] == store_sources[1] {
        return Err(BrowserCookieImportError::Cookie(
            CookieError::InvalidImportOrder,
        ));
    }
    match profile.browser() {
        BrowserKind::Firefox | BrowserKind::Zen => {
            import_gecko(profile, store_sources[0], allowlist).map(|import| vec![import])
        }
        BrowserKind::Chromium
        | BrowserKind::GoogleChrome
        | BrowserKind::Brave
        | BrowserKind::BraveOrigin
        | BrowserKind::MicrosoftEdge => {
            import_ordered_chromium_stores(profile, store_sources, allowlist, decryptor)
        }
    }
}

struct CanonicalDomainRule {
    domain: Zeroizing<String>,
    policy: BrowserCookieDomainPolicy,
}

struct StoredCookieDomain {
    domain: Zeroizing<String>,
    kind: CookieDomainKind,
}

fn import_gecko(
    profile: &BrowserProfile,
    source: CookieSourceId,
    allowlist: &BrowserCookieDomainAllowlist,
) -> Result<CookieImport, BrowserCookieImportError> {
    let snapshot = ReadOnlySqliteSnapshot::open(profile.path(), "cookies.sqlite")
        .map_err(BrowserCookieImportError::Snapshot)?;
    let query = build_query(
        "host, name, path, expiry, isSecure, value",
        "moz_cookies",
        "host",
        allowlist,
    );
    let records = query_records(
        snapshot.connection(),
        &query,
        allowlist,
        None,
        |row, _raw_host, domain| {
            let name = bounded_text(row, 1, MAX_COOKIE_NAME_BYTES)?;
            let path = bounded_text(row, 2, MAX_COOKIE_PATH_BYTES)?;
            let expires_at = firefox_expiry(integer(row, 3)?)?;
            let secure = sqlite_boolean(row, 4)?;
            let value = bounded_text(row, 5, MAX_COOKIE_VALUE_BYTES)?;
            cookie_record(name, value, domain, path, secure, expires_at).map(Some)
        },
    )?;
    CookieImport::new(source, records).map_err(BrowserCookieImportError::Cookie)
}

fn import_chromium(
    profile: &BrowserProfile,
    source: CookieSourceId,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<CookieImport, BrowserCookieImportError> {
    let snapshot = match ReadOnlySqliteSnapshot::open(profile.path(), "Network/Cookies") {
        Ok(snapshot) => snapshot,
        Err(SqliteSnapshotError::Missing) => {
            ReadOnlySqliteSnapshot::open(profile.path(), "Cookies")
                .map_err(BrowserCookieImportError::Snapshot)?
        }
        Err(error) => return Err(BrowserCookieImportError::Snapshot(error)),
    };
    let store = read_chromium_snapshot(
        profile.browser(),
        snapshot.connection(),
        allowlist,
        decryptor,
        None,
    )?;
    if store.records.is_empty() && store.saw_unavailable_encryption {
        return Err(BrowserCookieImportError::EncryptedCookiesUnavailable);
    }
    CookieImport::new(
        source,
        store
            .records
            .into_iter()
            .map(|record| record.record)
            .collect(),
    )
    .map_err(BrowserCookieImportError::Cookie)
}

fn import_merged_chromium(
    profile: &BrowserProfile,
    source: CookieSourceId,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<CookieImport, BrowserCookieImportError> {
    let (network, primary) = read_chromium_stores(profile, allowlist, decryptor)?;
    let saw_unavailable_encryption =
        stores_saw_unavailable_encryption(network.as_ref(), primary.as_ref());
    let records = merge_chromium_records(
        network.map_or_else(Vec::new, |store| store.records),
        primary.map_or_else(Vec::new, |store| store.records),
    );
    if records.is_empty() && saw_unavailable_encryption {
        return Err(BrowserCookieImportError::EncryptedCookiesUnavailable);
    }
    CookieImport::new(source, records).map_err(BrowserCookieImportError::Cookie)
}

fn import_ordered_chromium_stores(
    profile: &BrowserProfile,
    store_sources: [CookieSourceId; 2],
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<Vec<CookieImport>, BrowserCookieImportError> {
    let (network, primary) = read_chromium_stores(profile, allowlist, decryptor)?;
    let saw_unavailable_encryption =
        stores_saw_unavailable_encryption(network.as_ref(), primary.as_ref());
    let has_records = network
        .as_ref()
        .is_some_and(|store| !store.records.is_empty())
        || primary
            .as_ref()
            .is_some_and(|store| !store.records.is_empty());
    if !has_records && saw_unavailable_encryption {
        return Err(BrowserCookieImportError::EncryptedCookiesUnavailable);
    }
    [network, primary]
        .into_iter()
        .zip(store_sources)
        .filter_map(|(store, source)| store.map(|store| (store, source)))
        .map(|(store, source)| {
            CookieImport::new(
                source,
                store
                    .records
                    .into_iter()
                    .map(|record| record.record)
                    .collect(),
            )
            .map_err(BrowserCookieImportError::Cookie)
        })
        .collect()
}

fn read_chromium_stores(
    profile: &BrowserProfile,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<(Option<ChromiumStoreRecords>, Option<ChromiumStoreRecords>), BrowserCookieImportError>
{
    let mut budget = QueryBudget::default();
    let network = read_chromium_store(
        profile,
        "Network/Cookies",
        allowlist,
        decryptor,
        &mut budget,
    )?;
    let primary = read_chromium_store(profile, "Cookies", allowlist, decryptor, &mut budget)?;
    if network.is_none() && primary.is_none() {
        return Err(BrowserCookieImportError::Snapshot(
            SqliteSnapshotError::Missing,
        ));
    }
    Ok((network, primary))
}

fn stores_saw_unavailable_encryption(
    network: Option<&ChromiumStoreRecords>,
    primary: Option<&ChromiumStoreRecords>,
) -> bool {
    network.is_some_and(|store| store.saw_unavailable_encryption)
        || primary.is_some_and(|store| store.saw_unavailable_encryption)
}

fn read_chromium_store(
    profile: &BrowserProfile,
    relative: &'static str,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
    budget: &mut QueryBudget,
) -> Result<Option<ChromiumStoreRecords>, BrowserCookieImportError> {
    let snapshot = match ReadOnlySqliteSnapshot::open(profile.path(), relative) {
        Ok(snapshot) => snapshot,
        Err(SqliteSnapshotError::Missing) => return Ok(None),
        Err(error) => return Err(BrowserCookieImportError::Snapshot(error)),
    };
    read_chromium_snapshot(
        profile.browser(),
        snapshot.connection(),
        allowlist,
        decryptor,
        Some(budget),
    )
    .map(Some)
}

fn read_chromium_snapshot(
    browser: BrowserKind,
    connection: &Connection,
    allowlist: &BrowserCookieDomainAllowlist,
    decryptor: &dyn ChromiumCookieDecryptor,
    budget: Option<&mut QueryBudget>,
) -> Result<ChromiumStoreRecords, BrowserCookieImportError> {
    let query = build_query(
        "host_key, name, path, expires_utc, is_secure, value, encrypted_value",
        "cookies",
        "host_key",
        allowlist,
    );
    let database_version = chromium_database_version(connection)?;
    let mut saw_unavailable_encryption = false;
    let records = query_records(
        connection,
        &query,
        allowlist,
        budget,
        |row, raw_host, domain| {
            let name = bounded_text(row, 1, MAX_COOKIE_NAME_BYTES)?;
            let path = bounded_text(row, 2, MAX_COOKIE_PATH_BYTES)?;
            let expires_at = chromium_expiry(integer(row, 3)?)?;
            let secure = sqlite_boolean(row, 4)?;
            let plaintext = bounded_text(row, 5, MAX_COOKIE_VALUE_BYTES)?;
            let encrypted = bounded_blob(row, 6, MAX_ENCRYPTED_VALUE_BYTES)?;

            if !plaintext.is_empty() && !encrypted.is_empty() {
                return Err(BrowserCookieImportError::MalformedData);
            }
            let record = if encrypted.is_empty() {
                cookie_record(name, plaintext, domain, path, secure, expires_at)?
            } else {
                match decryptor.decrypt(browser, encrypted) {
                    Ok(value) => {
                        let value = chromium_decrypted_value(raw_host, database_version, &value)?;
                        cookie_record(name, value.as_str(), domain, path, secure, expires_at)?
                    }
                    Err(ChromiumCookieDecryptionError::Unavailable) => {
                        saw_unavailable_encryption = true;
                        return Ok(None);
                    }
                    Err(ChromiumCookieDecryptionError::Failed) => {
                        return Err(BrowserCookieImportError::DecryptionFailed);
                    }
                }
            };
            Ok(Some(ChromiumCookieRecord {
                key: ChromiumCookieKey {
                    name: name.to_owned(),
                    domain: domain.domain.as_str().to_owned(),
                    domain_kind: domain.kind,
                    path: path.to_owned(),
                },
                expires_at,
                record,
            }))
        },
    )?;
    Ok(ChromiumStoreRecords {
        records,
        saw_unavailable_encryption,
    })
}

fn merge_chromium_records(
    network: Vec<ChromiumCookieRecord>,
    primary: Vec<ChromiumCookieRecord>,
) -> Vec<CookieRecord> {
    let mut indexes = HashMap::<ChromiumCookieKey, usize>::new();
    let mut retained = Vec::<RetainedChromiumCookie>::new();
    for candidate in network.into_iter().chain(primary) {
        match indexes.entry(candidate.key) {
            Entry::Occupied(entry) => {
                let slot = &mut retained[*entry.get()];
                if should_replace_cookie(slot.expires_at, candidate.expires_at) {
                    *slot = RetainedChromiumCookie {
                        expires_at: candidate.expires_at,
                        record: candidate.record,
                    };
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(retained.len());
                retained.push(RetainedChromiumCookie {
                    expires_at: candidate.expires_at,
                    record: candidate.record,
                });
            }
        }
    }
    retained.into_iter().map(|record| record.record).collect()
}

fn should_replace_cookie(
    existing: Option<OffsetDateTime>,
    candidate: Option<OffsetDateTime>,
) -> bool {
    match (existing, candidate) {
        (Some(existing), Some(candidate)) => candidate > existing,
        (None, Some(_)) => true,
        (Some(_) | None, None) => false,
    }
}

struct ChromiumStoreRecords {
    records: Vec<ChromiumCookieRecord>,
    saw_unavailable_encryption: bool,
}

struct ChromiumCookieRecord {
    key: ChromiumCookieKey,
    expires_at: Option<OffsetDateTime>,
    record: CookieRecord,
}

#[derive(PartialEq, Eq, Hash)]
struct ChromiumCookieKey {
    name: String,
    domain: String,
    domain_kind: CookieDomainKind,
    path: String,
}

struct RetainedChromiumCookie {
    expires_at: Option<OffsetDateTime>,
    record: CookieRecord,
}

fn query_records<T, F>(
    connection: &Connection,
    query: &BoundedQuery,
    allowlist: &BrowserCookieDomainAllowlist,
    mut budget: Option<&mut QueryBudget>,
    mut decode: F,
) -> Result<Vec<T>, BrowserCookieImportError>
where
    F: FnMut(&Row<'_>, &str, &StoredCookieDomain) -> Result<Option<T>, BrowserCookieImportError>,
{
    let mut statement = connection
        .prepare(&query.sql)
        .map_err(|_| BrowserCookieImportError::MalformedSchema)?;
    for (index, binding) in query.bindings.iter().enumerate() {
        statement
            .raw_bind_parameter(index + 1, binding.as_str())
            .map_err(|_| BrowserCookieImportError::MalformedSchema)?;
    }
    let row_limit = i64::try_from(MAX_BROWSER_COOKIE_ROWS + 1)
        .map_err(|_| BrowserCookieImportError::TooManyRows)?;
    statement
        .raw_bind_parameter(query.bindings.len() + 1, row_limit)
        .map_err(|_| BrowserCookieImportError::MalformedSchema)?;

    let mut rows = statement.raw_query();
    let mut records = Vec::new();
    let mut row_count = 0_usize;
    while let Some(row) = rows
        .next()
        .map_err(|_| BrowserCookieImportError::MalformedData)?
    {
        row_count = row_count
            .checked_add(1)
            .ok_or(BrowserCookieImportError::TooManyRows)?;
        if row_count > MAX_BROWSER_COOKIE_ROWS {
            return Err(BrowserCookieImportError::TooManyRows);
        }
        if let Some(budget) = budget.as_deref_mut() {
            budget.inspect(row)?;
        }
        let raw_host = bounded_text(row, 0, MAX_COOKIE_HOST_BYTES)?;
        let domain = canonical_stored_cookie_domain(raw_host)?;
        if !allowlist.matches(domain.domain.as_str()) {
            continue;
        }
        if let Some(record) = decode(row, raw_host, &domain)? {
            records.push(record);
        }
    }
    Ok(records)
}

#[derive(Default)]
struct QueryBudget {
    rows: usize,
    bytes: usize,
}

impl QueryBudget {
    fn inspect(&mut self, row: &Row<'_>) -> Result<(), BrowserCookieImportError> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(BrowserCookieImportError::TooManyRows)?;
        if self.rows > MAX_BROWSER_COOKIE_ROWS {
            return Err(BrowserCookieImportError::TooManyRows);
        }

        let row_bytes = (0..row.as_ref().column_count()).try_fold(0_usize, |total, index| {
            let value = row
                .get_ref(index)
                .map_err(|_| BrowserCookieImportError::MalformedData)?;
            let bytes = match value {
                ValueRef::Null => 0,
                ValueRef::Integer(_) | ValueRef::Real(_) => size_of::<i64>(),
                ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes.len(),
            };
            total
                .checked_add(bytes)
                .ok_or(BrowserCookieImportError::TooManyBytes)
        })?;
        self.bytes = self
            .bytes
            .checked_add(row_bytes)
            .filter(|bytes| *bytes <= MAX_BROWSER_COOKIE_BYTES)
            .ok_or(BrowserCookieImportError::TooManyBytes)?;
        Ok(())
    }
}

struct BoundedQuery {
    sql: String,
    bindings: Vec<Zeroizing<String>>,
}

fn build_query(
    columns: &str,
    table: &str,
    host_column: &str,
    allowlist: &BrowserCookieDomainAllowlist,
) -> BoundedQuery {
    let mut clauses = Vec::<&str>::with_capacity(allowlist.rules.len());
    let mut bindings = Vec::<Zeroizing<String>>::with_capacity(allowlist.rules.len() * 2);
    for rule in &allowlist.rules {
        match rule.policy {
            BrowserCookieDomainPolicy::Exact => {
                clauses.push("({HOST} = ? COLLATE NOCASE OR {HOST} = ? COLLATE NOCASE)");
                bindings.push(rule.domain.clone());
                bindings.push(Zeroizing::new(format!(".{}", rule.domain.as_str())));
            }
            BrowserCookieDomainPolicy::DomainAndSubdomains => {
                clauses.push(
                    "({HOST} = ? COLLATE NOCASE OR {HOST} LIKE ? ESCAPE '\\' COLLATE NOCASE)",
                );
                bindings.push(rule.domain.clone());
                let escaped = escape_like(rule.domain.as_str());
                bindings.push(Zeroizing::new(format!("%.{escaped}")));
            }
        }
    }
    let predicate = clauses.join(" OR ").replace("{HOST}", host_column);
    let sql = format!(
        "SELECT {columns} FROM {table} WHERE ({predicate}) \
         ORDER BY {host_column} COLLATE BINARY, name COLLATE BINARY, path COLLATE BINARY, rowid \
         LIMIT ?"
    );
    BoundedQuery { sql, bindings }
}

fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn bounded_text<'row>(
    row: &'row Row<'_>,
    index: usize,
    maximum: usize,
) -> Result<&'row str, BrowserCookieImportError> {
    let value = row
        .get_ref(index)
        .map_err(|_| BrowserCookieImportError::MalformedData)?;
    let ValueRef::Text(bytes) = value else {
        return Err(BrowserCookieImportError::MalformedData);
    };
    if bytes.len() > maximum {
        return Err(BrowserCookieImportError::OversizedField);
    }
    std::str::from_utf8(bytes).map_err(|_| BrowserCookieImportError::MalformedData)
}

fn bounded_blob<'row>(
    row: &'row Row<'_>,
    index: usize,
    maximum: usize,
) -> Result<&'row [u8], BrowserCookieImportError> {
    let value = row
        .get_ref(index)
        .map_err(|_| BrowserCookieImportError::MalformedData)?;
    let bytes = match value {
        ValueRef::Blob(bytes) => bytes,
        ValueRef::Null => &[],
        _ => return Err(BrowserCookieImportError::MalformedData),
    };
    if bytes.len() > maximum {
        return Err(BrowserCookieImportError::OversizedField);
    }
    Ok(bytes)
}

fn integer(row: &Row<'_>, index: usize) -> Result<i64, BrowserCookieImportError> {
    match row
        .get_ref(index)
        .map_err(|_| BrowserCookieImportError::MalformedData)?
    {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(BrowserCookieImportError::MalformedData),
    }
}

fn sqlite_boolean(row: &Row<'_>, index: usize) -> Result<bool, BrowserCookieImportError> {
    match integer(row, index)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BrowserCookieImportError::MalformedData),
    }
}

fn chromium_database_version(connection: &Connection) -> Result<u32, BrowserCookieImportError> {
    let mut statement = connection
        .prepare("SELECT value FROM meta WHERE key = ?1 LIMIT 2")
        .map_err(|_| BrowserCookieImportError::MalformedSchema)?;
    let mut rows = statement
        .query(["version"])
        .map_err(|_| BrowserCookieImportError::MalformedSchema)?;
    let row = rows
        .next()
        .map_err(|_| BrowserCookieImportError::MalformedData)?
        .ok_or(BrowserCookieImportError::MalformedSchema)?;
    let value = row
        .get_ref(0)
        .map_err(|_| BrowserCookieImportError::MalformedData)?;
    let version = match value {
        ValueRef::Integer(value) => u32::try_from(value)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(BrowserCookieImportError::MalformedData)?,
        ValueRef::Text(bytes) => {
            if bytes.is_empty() || bytes.len() > MAX_CHROMIUM_META_VERSION_BYTES {
                return Err(BrowserCookieImportError::MalformedData);
            }
            let text =
                std::str::from_utf8(bytes).map_err(|_| BrowserCookieImportError::MalformedData)?;
            if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(BrowserCookieImportError::MalformedData);
            }
            text.parse::<u32>()
                .ok()
                .filter(|value| *value != 0)
                .ok_or(BrowserCookieImportError::MalformedData)?
        }
        _ => return Err(BrowserCookieImportError::MalformedData),
    };
    if rows
        .next()
        .map_err(|_| BrowserCookieImportError::MalformedData)?
        .is_some()
    {
        return Err(BrowserCookieImportError::MalformedData);
    }
    if version > MAX_SUPPORTED_CHROMIUM_DATABASE_VERSION {
        return Err(BrowserCookieImportError::MalformedSchema);
    }
    Ok(version)
}

fn chromium_decrypted_value(
    raw_host: &str,
    database_version: u32,
    plaintext: &[u8],
) -> Result<Zeroizing<String>, BrowserCookieImportError> {
    let value = if database_version >= 24 {
        if plaintext.len() < CHROMIUM_HOST_DIGEST_BYTES {
            return Err(BrowserCookieImportError::DecryptionFailed);
        }
        let expected = Sha256::digest(raw_host.as_bytes());
        if plaintext[..CHROMIUM_HOST_DIGEST_BYTES] != expected[..] {
            return Err(BrowserCookieImportError::DecryptionFailed);
        }
        &plaintext[CHROMIUM_HOST_DIGEST_BYTES..]
    } else {
        plaintext
    };
    if value.len() > MAX_COOKIE_VALUE_BYTES {
        return Err(BrowserCookieImportError::OversizedField);
    }
    let value =
        std::str::from_utf8(value).map_err(|_| BrowserCookieImportError::DecryptionFailed)?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn firefox_expiry(raw: i64) -> Result<Option<OffsetDateTime>, BrowserCookieImportError> {
    if raw == 0 {
        return Ok(None);
    }
    if raw < 0 {
        return Err(BrowserCookieImportError::MalformedData);
    }
    OffsetDateTime::from_unix_timestamp(raw)
        .map(Some)
        .map_err(|_| BrowserCookieImportError::MalformedData)
}

fn chromium_expiry(raw: i64) -> Result<Option<OffsetDateTime>, BrowserCookieImportError> {
    if raw == 0 {
        return Ok(None);
    }
    if raw < 0 {
        return Err(BrowserCookieImportError::MalformedData);
    }
    let unix_microseconds = raw
        .checked_sub(CHROMIUM_TO_UNIX_EPOCH_MICROSECONDS)
        .ok_or(BrowserCookieImportError::MalformedData)?;
    let seconds = unix_microseconds.div_euclid(MICROSECONDS_PER_SECOND);
    let microseconds = unix_microseconds.rem_euclid(MICROSECONDS_PER_SECOND);
    let nanoseconds = u32::try_from(microseconds)
        .ok()
        .and_then(|value| value.checked_mul(1_000))
        .ok_or(BrowserCookieImportError::MalformedData)?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .and_then(|timestamp| timestamp.replace_nanosecond(nanoseconds))
        .map(Some)
        .map_err(|_| BrowserCookieImportError::MalformedData)
}

fn cookie_record(
    name: &str,
    value: &str,
    domain: &StoredCookieDomain,
    path: &str,
    secure: bool,
    expires_at: Option<OffsetDateTime>,
) -> Result<CookieRecord, BrowserCookieImportError> {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain: domain.domain.as_str(),
        domain_kind: domain.kind,
        path,
        secure,
        expires_at,
    })
    .map_err(BrowserCookieImportError::Cookie)
}

fn canonical_allowlist_domain(
    raw: &str,
    policy: BrowserCookieDomainPolicy,
) -> Result<Zeroizing<String>, BrowserCookieImportError> {
    if raw.is_empty()
        || raw.len() > MAX_ALLOWLIST_DOMAIN_INPUT_BYTES
        || raw.starts_with('.')
        || raw.ends_with('.')
        || raw.contains('%')
        || raw.chars().any(char::is_control)
        || raw.chars().any(char::is_whitespace)
    {
        return Err(BrowserCookieImportError::InvalidAllowlist);
    }
    let Host::Domain(domain) =
        Host::parse(raw).map_err(|_| BrowserCookieImportError::InvalidAllowlist)?
    else {
        return Err(BrowserCookieImportError::InvalidAllowlist);
    };
    let domain = Zeroizing::new(domain);
    validate_canonical_domain(domain.as_str())
        .map_err(|_| BrowserCookieImportError::InvalidAllowlist)?;
    if domain.as_str() == "localhost" {
        return (policy == BrowserCookieDomainPolicy::Exact)
            .then_some(domain)
            .ok_or(BrowserCookieImportError::InvalidAllowlist);
    }
    if looks_like_public_suffix(domain.as_str()) {
        return Err(BrowserCookieImportError::InvalidAllowlist);
    }
    Ok(domain)
}

fn canonical_stored_cookie_domain(
    raw: &str,
) -> Result<StoredCookieDomain, BrowserCookieImportError> {
    if raw.is_empty()
        || raw.len() > MAX_COOKIE_HOST_BYTES
        || raw.ends_with('.')
        || raw.contains('%')
        || raw.chars().any(char::is_control)
        || raw.chars().any(char::is_whitespace)
    {
        return Err(BrowserCookieImportError::MalformedData);
    }
    let (raw, kind) = if let Some(domain) = raw.strip_prefix('.') {
        if domain.is_empty() || domain.starts_with('.') {
            return Err(BrowserCookieImportError::MalformedData);
        }
        (domain, CookieDomainKind::Domain)
    } else {
        (raw, CookieDomainKind::HostOnly)
    };
    let Host::Domain(domain) =
        Host::parse(raw).map_err(|_| BrowserCookieImportError::MalformedData)?
    else {
        return Err(BrowserCookieImportError::MalformedData);
    };
    let domain = Zeroizing::new(domain);
    validate_canonical_domain(domain.as_str())?;
    Ok(StoredCookieDomain { domain, kind })
}

fn validate_canonical_domain(domain: &str) -> Result<(), BrowserCookieImportError> {
    if domain.is_empty()
        || domain.len() > MAX_CANONICAL_DOMAIN_BYTES
        || !domain.is_ascii()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        return Err(BrowserCookieImportError::MalformedData);
    }
    Ok(())
}

fn looks_like_public_suffix(domain: &str) -> bool {
    const PRIVATE_SUFFIXES: &[&str] = &[
        "appspot.com",
        "azurewebsites.net",
        "cloudfront.net",
        "firebaseapp.com",
        "github.io",
        "gitlab.io",
        "herokuapp.com",
        "netlify.app",
        "pages.dev",
        "vercel.app",
    ];
    const CCTLD_SECOND_LEVELS: &[&str] = &[
        "ac", "co", "com", "edu", "firm", "gen", "go", "gov", "id", "ind", "lg", "mil", "ne",
        "net", "or", "org", "sch",
    ];

    let labels = domain.split('.').collect::<Vec<_>>();
    labels.len() < 2
        || PRIVATE_SUFFIXES.contains(&domain)
        || labels.len() == 2 && labels[1].len() == 2 && CCTLD_SECOND_LEVELS.contains(&labels[0])
}
