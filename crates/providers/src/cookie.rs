//! Bounded, host-scoped cookie normalization and deterministic request selection.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::hash::{Hash, Hasher};

use thiserror::Error;
use time::OffsetDateTime;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of cookie records accepted from one source.
pub const MAX_COOKIES_PER_IMPORT: usize = 4_096;
/// Maximum number of records retained from the selected source in one jar.
pub const MAX_COOKIE_JAR_RECORDS: usize = MAX_COOKIES_PER_IMPORT;
/// Maximum aggregate cookie bytes retained by one jar.
pub const MAX_COOKIE_JAR_BYTES: usize = 8 * 1024 * 1024;
/// Maximum serialized `Cookie` request-header size.
pub const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;

const MAX_IMPORT_SOURCES: usize = 64;
const MAX_CAPTURE_BYTES: usize = 128 * 1024;
const MAX_CAPTURE_PAIRS: usize = 512;
const MAX_CAPTURE_TOKENS: usize = 512;
const MAX_COOKIE_NAME_BYTES: usize = 256;
const MAX_COOKIE_VALUE_BYTES: usize = 16 * 1024;
const MAX_DOMAIN_INPUT_BYTES: usize = 1_024;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_REQUEST_URL_BYTES: usize = 16 * 1024;

/// Fail-closed errors from cookie validation and selection.
///
/// Variants intentionally carry no input data so `Debug` and `Display` cannot
/// reveal cookie or account information.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    /// A cookie name, value, domain, path, or capture is malformed.
    #[error("invalid cookie data")]
    InvalidRecord,
    /// A jar or import exceeds its fixed record or byte limits.
    #[error("cookie data exceeds the configured limit")]
    JarTooLarge,
    /// Source priority is empty, duplicated, or inconsistent with the imports.
    #[error("invalid cookie source order")]
    InvalidImportOrder,
    /// A request URL is outside the selected HTTPS/loopback policy.
    #[error("invalid cookie request URL")]
    InvalidRequestUrl,
    /// Matching cookies cannot fit in the bounded request header.
    #[error("cookie request header exceeds the configured limit")]
    HeaderTooLarge,
}

/// Whether a record came from an exact host or a `Domain` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CookieDomainKind {
    /// Match only the canonical host stored in the record.
    HostOnly,
    /// Match the canonical domain and its dot-delimited subdomains.
    Domain,
}

/// Borrowed input used to construct one validated cookie record.
#[derive(Clone, Copy)]
pub struct CookieRecordSpec<'a> {
    /// RFC token cookie name.
    pub name: &'a str,
    /// RFC 6265 cookie-octet value.
    pub value: &'a str,
    /// Host or `Domain` attribute. One leading dot is accepted for domain
    /// records and removed during canonicalization.
    pub domain: &'a str,
    /// Exact-host or domain-cookie semantics.
    pub domain_kind: CookieDomainKind,
    /// Absolute cookie path.
    pub path: &'a str,
    /// Whether the cookie requires a secure request.
    pub secure: bool,
    /// Absolute expiry; `None` represents a session cookie.
    pub expires_at: Option<OffsetDateTime>,
}

impl Debug for CookieRecordSpec<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieRecordSpec(<redacted>)")
    }
}

/// One validated, zeroizing cookie record.
pub struct CookieRecord {
    identity: CookieIdentity,
    data: CookieData,
}

impl CookieRecord {
    /// Validates and canonicalizes one RFC 6265-style record.
    ///
    /// # Errors
    ///
    /// Rejects invalid names/values, unsafe domains, IP domain cookies,
    /// relative paths, control characters, and oversized fields.
    pub fn new(spec: CookieRecordSpec<'_>) -> Result<Self, CookieError> {
        validate_cookie_name(spec.name)?;
        validate_cookie_value(spec.value)?;
        validate_cookie_path(spec.path)?;
        let domain = canonical_cookie_domain(spec.domain, spec.domain_kind)?;

        Ok(Self {
            identity: CookieIdentity {
                name: Zeroizing::new(spec.name.to_owned()),
                domain,
                domain_kind: spec.domain_kind,
                path: Zeroizing::new(spec.path.to_owned()),
            },
            data: CookieData {
                value: Zeroizing::new(spec.value.to_owned()),
                secure: spec.secure,
                expires_at: spec.expires_at,
            },
        })
    }

    fn byte_len(&self) -> Result<usize, CookieError> {
        self.identity
            .name
            .len()
            .checked_add(self.data.value.len())
            .and_then(|value| value.checked_add(self.identity.domain.len()))
            .and_then(|value| value.checked_add(self.identity.path.len()))
            .ok_or(CookieError::JarTooLarge)
    }
}

impl Debug for CookieRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieRecord(<redacted>)")
    }
}

impl Clone for CookieRecord {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            data: self.data.clone(),
        }
    }
}

/// Opaque identifier used to express provider-owned browser/source priority.
///
/// The shared cookie layer does not discover browsers and therefore does not
/// attach global meaning to these IDs. Callers map their typed browser enum to
/// stable IDs and supply the desired order explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CookieSourceId(u16);

impl CookieSourceId {
    /// Conventional ID for an explicitly supplied manual capture.
    pub const MANUAL: Self = Self(0);

    /// Creates a stable provider-owned source ID.
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
}

/// Deterministic first-to-last source priority.
pub struct CookieImportOrder {
    sources: Vec<CookieSourceId>,
}

/// Compatibility name for provider browser preference lists.
pub type BrowserCookieImportOrder = CookieImportOrder;

impl CookieImportOrder {
    /// Creates a non-empty source order with no duplicates.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, or excessively large lists.
    pub fn new(sources: impl IntoIterator<Item = CookieSourceId>) -> Result<Self, CookieError> {
        let sources = sources.into_iter().collect::<Vec<_>>();
        if sources.is_empty() || sources.len() > MAX_IMPORT_SOURCES {
            return Err(CookieError::InvalidImportOrder);
        }
        let unique = sources.iter().copied().collect::<HashSet<_>>();
        if unique.len() != sources.len() {
            return Err(CookieError::InvalidImportOrder);
        }
        Ok(Self { sources })
    }

    /// Ordered source IDs.
    #[must_use]
    pub fn sources(&self) -> &[CookieSourceId] {
        &self.sources
    }

    fn rank(&self, source: CookieSourceId) -> Option<usize> {
        self.sources
            .iter()
            .position(|candidate| *candidate == source)
    }
}

impl Debug for CookieImportOrder {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieImportOrder")
            .field("source_count", &self.sources.len())
            .finish()
    }
}

impl Clone for CookieImportOrder {
    fn clone(&self) -> Self {
        Self {
            sources: self.sources.clone(),
        }
    }
}

/// One bounded source result ready for deterministic jar assembly.
pub struct CookieImport {
    source: CookieSourceId,
    records: Vec<CookieRecord>,
    bytes: usize,
}

impl CookieImport {
    /// Creates one bounded import.
    ///
    /// # Errors
    ///
    /// Rejects excessive record counts or aggregate bytes.
    pub fn new(source: CookieSourceId, records: Vec<CookieRecord>) -> Result<Self, CookieError> {
        if records.len() > MAX_COOKIES_PER_IMPORT {
            return Err(CookieError::JarTooLarge);
        }
        let bytes = records.iter().try_fold(0_usize, |total, record| {
            total
                .checked_add(record.byte_len()?)
                .ok_or(CookieError::JarTooLarge)
        })?;
        if bytes > MAX_COOKIE_JAR_BYTES {
            return Err(CookieError::JarTooLarge);
        }
        Ok(Self {
            source,
            records,
            bytes,
        })
    }

    /// Binds a normalized manual capture to the target's exact canonical host.
    /// All produced records use `/` and cannot become domain cookies.
    ///
    /// # Errors
    ///
    /// Returns a redacted validation error for an invalid capture.
    pub fn from_host_only_capture(
        source: CookieSourceId,
        raw: &str,
        target: &ValidatedCookieUrl,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Self, CookieError> {
        let normalized =
            CookieHeaderNormalizer::normalize(Some(raw))?.ok_or(CookieError::InvalidRecord)?;
        Self::from_normalized_host_only(source, normalized, target, expires_at)
    }

    /// Binds already-normalized pairs to the target's exact canonical host.
    ///
    /// # Errors
    ///
    /// Returns a redacted size or validation error.
    pub fn from_normalized_host_only(
        source: CookieSourceId,
        normalized: NormalizedCookieHeader,
        target: &ValidatedCookieUrl,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Self, CookieError> {
        let mut records = Vec::with_capacity(normalized.pairs.len());
        for pair in normalized.pairs {
            records.push(CookieRecord {
                identity: CookieIdentity {
                    name: pair.name,
                    domain: target.host.clone(),
                    domain_kind: CookieDomainKind::HostOnly,
                    path: Zeroizing::new("/".to_owned()),
                },
                data: CookieData {
                    value: pair.value,
                    secure: target.secure,
                    expires_at,
                },
            });
        }
        Self::new(source, records)
    }
}

impl Debug for CookieImport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieImport")
            .field("source", &self.source)
            .field("record_count", &self.records.len())
            .field("byte_count", &self.bytes)
            .finish()
    }
}

/// Explicit transport policy for request URLs that may receive cookies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieUrlPolicy {
    /// Require HTTPS for every request.
    HttpsOnly,
    /// Also permit HTTP for the exact `localhost` or IP loopback host.
    LoopbackHttp,
}

/// A validated request URL required by [`CookieJar::header_for`].
pub struct ValidatedCookieUrl {
    url: Url,
    host: Zeroizing<String>,
    host_is_ip: bool,
    secure: bool,
}

impl ValidatedCookieUrl {
    /// Parses a request URL under an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Rejects credentials, fragments, missing/invalid hosts, non-HTTPS
    /// schemes, and public HTTP.
    pub fn parse(raw: &str, policy: CookieUrlPolicy) -> Result<Self, CookieError> {
        if raw.is_empty() || raw.len() > MAX_REQUEST_URL_BYTES || raw.chars().any(char::is_control)
        {
            return Err(CookieError::InvalidRequestUrl);
        }
        let url = Url::parse(raw).map_err(|_| CookieError::InvalidRequestUrl)?;
        Self::new(url, policy)
    }

    /// Validates an already-parsed request URL.
    ///
    /// # Errors
    ///
    /// Applies the same restrictions as [`Self::parse`].
    pub fn new(url: Url, policy: CookieUrlPolicy) -> Result<Self, CookieError> {
        if url.as_str().len() > MAX_REQUEST_URL_BYTES
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(CookieError::InvalidRequestUrl);
        }
        let host = url.host().ok_or(CookieError::InvalidRequestUrl)?;
        let secure = match url.scheme() {
            "https" => true,
            "http" if policy == CookieUrlPolicy::LoopbackHttp && host_is_loopback(&host) => false,
            _ => return Err(CookieError::InvalidRequestUrl),
        };
        let (host, host_is_ip) = canonical_request_host(&host)?;
        Ok(Self {
            url,
            host,
            host_is_ip,
            secure,
        })
    }

    /// Exact validated URL used for the request.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Whether this URL uses HTTPS.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }
}

impl Debug for ValidatedCookieUrl {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedCookieUrl(<redacted>)")
    }
}

impl Clone for ValidatedCookieUrl {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            host: self.host.clone(),
            host_is_ip: self.host_is_ip,
            secure: self.secure,
        }
    }
}

/// A provider-owned cookie jar with no ambient or global browser state.
pub struct CookieJar {
    entries: HashMap<CookieIdentity, CookieData>,
    record_count: usize,
    byte_count: usize,
}

impl CookieJar {
    /// Selects the highest-priority non-empty import as one isolated jar.
    /// Input batch order has no effect. Lower-priority sources never contribute
    /// records or per-cookie fallbacks; the last duplicate within the selected
    /// source wins.
    ///
    /// # Errors
    ///
    /// Rejects unknown/duplicate source batches and selected-source overflow.
    pub fn from_imports(
        order: &CookieImportOrder,
        imports: impl IntoIterator<Item = CookieImport>,
    ) -> Result<Self, CookieError> {
        let mut imports = imports.into_iter().collect::<Vec<_>>();
        if imports.len() > order.sources.len() {
            return Err(CookieError::InvalidImportOrder);
        }

        let mut seen = HashSet::with_capacity(imports.len());
        for import in &imports {
            if order.rank(import.source).is_none() || !seen.insert(import.source) {
                return Err(CookieError::InvalidImportOrder);
            }
        }
        imports.sort_by_key(|import| order.rank(import.source).unwrap_or(usize::MAX));

        let Some(selected) = imports
            .into_iter()
            .find(|import| !import.records.is_empty())
        else {
            return Ok(Self {
                entries: HashMap::new(),
                record_count: 0,
                byte_count: 0,
            });
        };
        let record_count = selected.records.len();
        let byte_count = selected.bytes;
        if record_count > MAX_COOKIE_JAR_RECORDS || byte_count > MAX_COOKIE_JAR_BYTES {
            return Err(CookieError::JarTooLarge);
        }

        let mut entries = HashMap::<CookieIdentity, CookieData>::new();
        for record in selected.records {
            entries.insert(record.identity, record.data);
        }

        Ok(Self {
            entries,
            record_count,
            byte_count,
        })
    }

    /// Selects active cookies for one exact validated URL and injected time.
    ///
    /// Matching follows host-only/domain, path-boundary, `Secure`, and expiry
    /// rules. The resulting header uses stable RFC-style longest-path-first
    /// ordering.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if the selected header exceeds its fixed cap.
    pub fn header_for(
        &self,
        target: &ValidatedCookieUrl,
        now: OffsetDateTime,
    ) -> Result<Option<CookieHeader>, CookieError> {
        let mut selected = Vec::<SelectedCookie<'_>>::new();
        for (identity, data) in &self.entries {
            if !identity.matches_host(target)
                || !path_matches(identity.path.as_str(), target.url.path())
                || data.secure && !target.secure
                || data.expires_at.is_some_and(|expires_at| expires_at <= now)
            {
                continue;
            }
            selected.push(SelectedCookie { identity, data });
        }

        selected.sort_by(|left, right| {
            right
                .identity
                .path
                .len()
                .cmp(&left.identity.path.len())
                .then_with(|| {
                    domain_kind_rank(left.identity.domain_kind)
                        .cmp(&domain_kind_rank(right.identity.domain_kind))
                })
                .then_with(|| right.identity.domain.len().cmp(&left.identity.domain.len()))
                .then_with(|| {
                    left.identity
                        .path
                        .as_bytes()
                        .cmp(right.identity.path.as_bytes())
                })
                .then_with(|| {
                    left.identity
                        .name
                        .as_bytes()
                        .cmp(right.identity.name.as_bytes())
                })
                .then_with(|| {
                    left.identity
                        .domain
                        .as_bytes()
                        .cmp(right.identity.domain.as_bytes())
                })
        });

        if selected.is_empty() {
            return Ok(None);
        }

        let header_size =
            selected
                .iter()
                .enumerate()
                .try_fold(0_usize, |total, (index, selected)| {
                    let separator = usize::from(index != 0) * 2;
                    let appended = selected
                        .identity
                        .name
                        .len()
                        .checked_add(1)
                        .and_then(|size| size.checked_add(selected.data.value.len()))
                        .and_then(|size| size.checked_add(separator))
                        .ok_or(CookieError::HeaderTooLarge)?;
                    total
                        .checked_add(appended)
                        .filter(|size| *size <= MAX_COOKIE_HEADER_BYTES)
                        .ok_or(CookieError::HeaderTooLarge)
                })?;

        let mut value = Zeroizing::new(String::with_capacity(header_size));
        for (index, selected) in selected.iter().enumerate() {
            if index != 0 {
                value.push_str("; ");
            }
            value.push_str(selected.identity.name.as_str());
            value.push('=');
            value.push_str(selected.data.value.as_str());
        }
        Ok(Some(CookieHeader(value)))
    }

    /// Number of records accepted from the selected source, including
    /// overwritten duplicates. Lower-priority imports are not counted.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Aggregate bytes accepted from the selected source.
    #[must_use]
    pub const fn byte_count(&self) -> usize {
        self.byte_count
    }

    /// Whether no records were imported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.record_count == 0
    }
}

impl Debug for CookieJar {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieJar")
            .field("record_count", &self.record_count)
            .field("byte_count", &self.byte_count)
            .finish_non_exhaustive()
    }
}

/// A zeroizing request-header value produced only for a validated URL.
pub struct CookieHeader(Zeroizing<String>);

impl CookieHeader {
    /// Borrows the header for immediate attachment to a typed request.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Header byte count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the header is empty. Jar-produced headers are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Debug for CookieHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieHeader(<redacted>)")
    }
}

/// Strict, bounded equivalent of the pinned manual Cookie/cURL normalizer.
pub struct CookieHeaderNormalizer;

impl CookieHeaderNormalizer {
    /// Extracts and validates cookie pairs from a raw header, quoted value, or
    /// common cURL `-H Cookie:`, `--cookie`, `-b`, and compact `-bfoo=bar`
    /// forms. Input is parsed as data and is never executed.
    ///
    /// # Errors
    ///
    /// Rejects malformed shell quoting, controls, invalid pairs, or oversize.
    pub fn normalize(raw: Option<&str>) -> Result<Option<NormalizedCookieHeader>, CookieError> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.len() > MAX_CAPTURE_BYTES
            || raw
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\t'))
        {
            return Err(CookieError::InvalidRecord);
        }

        let candidate = extract_cookie_capture(raw)?;
        let pairs = parse_cookie_pairs(candidate.as_str())?;
        Ok(Some(NormalizedCookieHeader { pairs }))
    }

    /// Normalizes a capture and keeps only exact, case-sensitive cookie names.
    ///
    /// # Errors
    ///
    /// Rejects invalid allowed names and malformed captures.
    pub fn filtered(
        raw: Option<&str>,
        allowed_names: &[&str],
    ) -> Result<Option<NormalizedCookieHeader>, CookieError> {
        if allowed_names.is_empty()
            || allowed_names
                .iter()
                .any(|name| validate_cookie_name(name).is_err())
        {
            return Err(CookieError::InvalidRecord);
        }
        let Some(mut normalized) = Self::normalize(raw)? else {
            return Ok(None);
        };
        normalized
            .pairs
            .retain(|pair| allowed_names.contains(&pair.name.as_str()));
        Ok((!normalized.pairs.is_empty()).then_some(normalized))
    }
}

/// Validated cookie pairs that must be host-bound before request use.
pub struct NormalizedCookieHeader {
    pairs: Vec<CookiePair>,
}

impl NormalizedCookieHeader {
    /// Number of normalized pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether no pairs remain after filtering.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

impl Debug for NormalizedCookieHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizedCookieHeader")
            .field("pair_count", &self.pairs.len())
            .finish()
    }
}

#[derive(Clone)]
struct CookieData {
    value: Zeroizing<String>,
    secure: bool,
    expires_at: Option<OffsetDateTime>,
}

struct CookieIdentity {
    name: Zeroizing<String>,
    domain: Zeroizing<String>,
    domain_kind: CookieDomainKind,
    path: Zeroizing<String>,
}

impl CookieIdentity {
    fn matches_host(&self, target: &ValidatedCookieUrl) -> bool {
        match self.domain_kind {
            CookieDomainKind::HostOnly => self.domain.as_str() == target.host.as_str(),
            CookieDomainKind::Domain => {
                if target.host_is_ip {
                    return false;
                }
                target.host.as_str() == self.domain.as_str()
                    || target
                        .host
                        .strip_suffix(self.domain.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

impl Clone for CookieIdentity {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            domain: self.domain.clone(),
            domain_kind: self.domain_kind,
            path: self.path.clone(),
        }
    }
}

impl PartialEq for CookieIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.domain_kind == other.domain_kind
            && self.name.as_str() == other.name.as_str()
            && self.domain.as_str() == other.domain.as_str()
            && self.path.as_str() == other.path.as_str()
    }
}

impl Eq for CookieIdentity {}

impl Hash for CookieIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain_kind.hash(state);
        self.name.as_bytes().hash(state);
        self.domain.as_bytes().hash(state);
        self.path.as_bytes().hash(state);
    }
}

struct CookiePair {
    name: Zeroizing<String>,
    value: Zeroizing<String>,
}

struct SelectedCookie<'a> {
    identity: &'a CookieIdentity,
    data: &'a CookieData,
}

fn validate_cookie_name(name: &str) -> Result<(), CookieError> {
    if name.is_empty()
        || name.len() > MAX_COOKIE_NAME_BYTES
        || !name.bytes().all(|byte| {
            byte.is_ascii()
                && (0x21..=0x7e).contains(&byte)
                && !matches!(
                    byte,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
    {
        return Err(CookieError::InvalidRecord);
    }
    Ok(())
}

fn validate_cookie_value(value: &str) -> Result<(), CookieError> {
    if value.len() > MAX_COOKIE_VALUE_BYTES
        || !value.bytes().all(|byte| {
            byte == 0x21
                || (0x23..=0x2b).contains(&byte)
                || (0x2d..=0x3a).contains(&byte)
                || (0x3c..=0x5b).contains(&byte)
                || (0x5d..=0x7e).contains(&byte)
        })
    {
        return Err(CookieError::InvalidRecord);
    }
    Ok(())
}

fn validate_cookie_path(path: &str) -> Result<(), CookieError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || !path.is_ascii()
        || path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b';' | b'?' | b'#' | b'\\'))
    {
        return Err(CookieError::InvalidRecord);
    }
    Ok(())
}

fn canonical_cookie_domain(
    raw: &str,
    kind: CookieDomainKind,
) -> Result<Zeroizing<String>, CookieError> {
    if raw.is_empty()
        || raw.len() > MAX_DOMAIN_INPUT_BYTES
        || raw.chars().any(char::is_control)
        || raw.chars().any(char::is_whitespace)
        || raw.contains('%')
        || raw.ends_with('.')
    {
        return Err(CookieError::InvalidRecord);
    }
    let domain = match kind {
        CookieDomainKind::HostOnly if raw.starts_with('.') => {
            return Err(CookieError::InvalidRecord);
        }
        CookieDomainKind::Domain => raw.strip_prefix('.').unwrap_or(raw),
        CookieDomainKind::HostOnly => raw,
    };
    if domain.is_empty() || domain.starts_with('.') {
        return Err(CookieError::InvalidRecord);
    }

    match Host::parse(domain).map_err(|_| CookieError::InvalidRecord)? {
        Host::Domain(domain) => {
            let domain = Zeroizing::new(domain);
            validate_canonical_domain(domain.as_str())?;
            if kind == CookieDomainKind::Domain && looks_like_public_suffix(domain.as_str()) {
                return Err(CookieError::InvalidRecord);
            }
            Ok(domain)
        }
        Host::Ipv4(address) => {
            if kind == CookieDomainKind::Domain {
                return Err(CookieError::InvalidRecord);
            }
            Ok(Zeroizing::new(address.to_string()))
        }
        Host::Ipv6(address) => {
            if kind == CookieDomainKind::Domain {
                return Err(CookieError::InvalidRecord);
            }
            Ok(Zeroizing::new(address.to_string()))
        }
    }
}

fn canonical_request_host(host: &Host<&str>) -> Result<(Zeroizing<String>, bool), CookieError> {
    match host {
        Host::Domain(domain) => {
            validate_canonical_domain(domain).map_err(|_| CookieError::InvalidRequestUrl)?;
            Ok((Zeroizing::new((*domain).to_owned()), false))
        }
        Host::Ipv4(address) => Ok((Zeroizing::new(address.to_string()), true)),
        Host::Ipv6(address) => Ok((Zeroizing::new(address.to_string()), true)),
    }
}

fn validate_canonical_domain(domain: &str) -> Result<(), CookieError> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_BYTES
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
        return Err(CookieError::InvalidRecord);
    }
    Ok(())
}

fn looks_like_public_suffix(domain: &str) -> bool {
    const PRIVATE_OR_MULTI_LABEL_SUFFIXES: &[&str] = &[
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
    if labels.len() < 2 || PRIVATE_OR_MULTI_LABEL_SUFFIXES.contains(&domain) {
        return true;
    }
    labels.len() == 2 && labels[1].len() == 2 && CCTLD_SECOND_LEVELS.contains(&labels[0])
}

fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| {
                cookie_path.ends_with('/') || suffix.as_bytes().first() == Some(&b'/')
            })
}

const fn domain_kind_rank(kind: CookieDomainKind) -> u8 {
    match kind {
        CookieDomainKind::HostOnly => 0,
        CookieDomainKind::Domain => 1,
    }
}

fn extract_cookie_capture(raw: &str) -> Result<Zeroizing<String>, CookieError> {
    let direct = strip_outer_quotes(raw.trim());
    if let Some(value) = strip_ascii_case_prefix(direct, "cookie:") {
        return owned_nonempty(value);
    }
    if direct.contains('=')
        && !direct.starts_with('-')
        && !direct
            .split_ascii_whitespace()
            .next()
            .is_some_and(|first| first.eq_ignore_ascii_case("curl"))
    {
        return owned_nonempty(direct);
    }

    let tokens = shell_tokens(raw)?;
    for index in 0..tokens.len() {
        let token = tokens[index].as_str();
        if token == "-H" || token == "--header" {
            if let Some(next) = tokens.get(index + 1)
                && let Some(value) = strip_ascii_case_prefix(next.as_str(), "cookie:")
            {
                return owned_nonempty(value);
            }
            continue;
        }
        if let Some(header) = token.strip_prefix("-H")
            && let Some(value) = strip_ascii_case_prefix(header, "cookie:")
        {
            return owned_nonempty(value);
        }
        if let Some(header) = token.strip_prefix("--header=")
            && let Some(value) = strip_ascii_case_prefix(header, "cookie:")
        {
            return owned_nonempty(value);
        }
        if let Some(value) = strip_ascii_case_prefix(token, "cookie:") {
            return owned_nonempty(value);
        }
    }
    for index in 0..tokens.len() {
        let token = tokens[index].as_str();
        if token == "-b" || token == "--cookie" {
            return tokens
                .get(index + 1)
                .ok_or(CookieError::InvalidRecord)
                .and_then(|value| owned_nonempty(value.as_str()));
        }
        if let Some(value) = token.strip_prefix("-b")
            && !value.is_empty()
        {
            return owned_nonempty(value);
        }
        if let Some(value) = token.strip_prefix("--cookie=") {
            return owned_nonempty(value);
        }
    }
    Err(CookieError::InvalidRecord)
}

fn shell_tokens(raw: &str) -> Result<Vec<Zeroizing<String>>, CookieError> {
    let mut tokens = Vec::<Zeroizing<String>>::new();
    let mut current = Zeroizing::new(String::with_capacity(raw.len()));
    let mut quote = None::<char>;
    let mut escaped = false;

    for character in raw.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_ascii_whitespace() && quote.is_none() {
            if !current.is_empty() {
                push_shell_token(&mut tokens, &mut current)?;
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err(CookieError::InvalidRecord);
    }
    if !current.is_empty() {
        push_shell_token(&mut tokens, &mut current)?;
    }
    Ok(tokens)
}

fn push_shell_token(
    tokens: &mut Vec<Zeroizing<String>>,
    current: &mut Zeroizing<String>,
) -> Result<(), CookieError> {
    if tokens.len() >= MAX_CAPTURE_TOKENS {
        return Err(CookieError::JarTooLarge);
    }
    tokens.push(Zeroizing::new(current.as_str().to_owned()));
    current.zeroize();
    Ok(())
}

fn parse_cookie_pairs(raw: &str) -> Result<Vec<CookiePair>, CookieError> {
    let raw = strip_outer_quotes(raw.trim()).trim();
    if raw.is_empty() {
        return Err(CookieError::InvalidRecord);
    }
    let mut pairs = Vec::new();
    let mut total = 0_usize;
    for part in raw.split(';') {
        let part = part.trim();
        let (name, value) = part.split_once('=').ok_or(CookieError::InvalidRecord)?;
        let name = name.trim();
        let value = value.trim();
        validate_cookie_name(name)?;
        validate_cookie_value(value)?;
        total = total
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(CookieError::JarTooLarge)?;
        if pairs.len() >= MAX_CAPTURE_PAIRS || total > MAX_COOKIE_HEADER_BYTES {
            return Err(CookieError::JarTooLarge);
        }
        pairs.push(CookiePair {
            name: Zeroizing::new(name.to_owned()),
            value: Zeroizing::new(value.to_owned()),
        });
    }
    Ok(pairs)
}

fn strip_outer_quotes(raw: &str) -> &str {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        &raw[1..raw.len() - 1]
    } else {
        raw
    }
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .map(|_| value[prefix.len()..].trim())
}

fn owned_nonempty(value: &str) -> Result<Zeroizing<String>, CookieError> {
    let value = strip_outer_quotes(value.trim()).trim();
    if value.is_empty() {
        return Err(CookieError::InvalidRecord);
    }
    Ok(Zeroizing::new(value.to_owned()))
}
