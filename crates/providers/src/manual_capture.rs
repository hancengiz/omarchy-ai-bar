//! Non-executing parsing of user-supplied Cookie, Authorization, and cURL captures.
//!
//! This module is deliberately a parser, not a shell wrapper. A pasted cURL
//! command is tokenized with a small, non-expanding grammar and is never passed
//! to a shell or subprocess. Providers must also declare both the credential
//! header classes they consume and the exact HTTPS hosts they recognize.

use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 32 * 1024;
const MAX_SECRET_BYTES: usize = 32 * 1024;
const MAX_TOKENS: usize = 256;
const MAX_HEADERS: usize = 32;
const MAX_HOSTS: usize = 32;
const MAX_FORWARDED_HEADERS: usize = 32;
const MAX_FORWARDED_VALUE_BYTES: usize = 16 * 1024;
const MAX_HEADER_NAME_BYTES: usize = 128;
const MAX_QUOTE_TRANSITIONS: usize = 512;

/// Credential-bearing HTTP header classes understood by manual capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaptureHeader {
    /// A complete HTTP `Cookie` field value.
    Cookie,
    /// A complete HTTP `Authorization` field value, including its scheme.
    Authorization,
}

impl CaptureHeader {
    const fn index(self) -> usize {
        match self {
            Self::Cookie => 0,
            Self::Authorization => 1,
        }
    }
}

/// A typed, exact loopback-host exception for isolated tests and local seams.
///
/// Constructing this value is intentionally separate from adding a normal
/// HTTPS host. Only exact `localhost`, IPv4 loopback, and IPv6 loopback names
/// are accepted.
#[derive(Clone, PartialEq, Eq)]
pub struct LoopbackCaptureHost {
    host: String,
}

impl LoopbackCaptureHost {
    /// Validates one exact loopback host without a scheme, port, or path.
    ///
    /// # Errors
    ///
    /// Returns [`ManualCaptureError::InvalidPolicy`] for non-loopback or
    /// malformed input.
    pub fn new(host: impl AsRef<str>) -> Result<Self, ManualCaptureError> {
        let host = normalize_host(host.as_ref())?;
        if !is_loopback_host(&host) {
            return Err(ManualCaptureError::InvalidPolicy);
        }
        Ok(Self { host })
    }
}

impl Debug for LoopbackCaptureHost {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoopbackCaptureHost(<redacted>)")
    }
}

/// Exact host and header authority granted to a manual capture parser.
#[derive(Clone)]
pub struct ManualCapturePolicy {
    https_hosts: Vec<String>,
    loopback_hosts: Vec<String>,
    allowed_headers: [bool; 2],
    forwarded_headers: Vec<String>,
    ignore_url_query: bool,
}

impl ManualCapturePolicy {
    /// Builds a policy from exact HTTPS hosts and accepted credential headers.
    ///
    /// Host entries contain only a DNS name or IP address: schemes, ports,
    /// paths, wildcards, and loopback entries are rejected. Loopback must be
    /// granted separately with [`Self::with_loopback_host`].
    ///
    /// # Errors
    ///
    /// Returns [`ManualCaptureError::InvalidPolicy`] when either list is empty,
    /// exceeds its bound, or contains malformed entries.
    pub fn new<Hosts, HostValue, Headers>(
        https_hosts: Hosts,
        allowed_headers: Headers,
    ) -> Result<Self, ManualCaptureError>
    where
        Hosts: IntoIterator<Item = HostValue>,
        HostValue: AsRef<str>,
        Headers: IntoIterator<Item = CaptureHeader>,
    {
        let mut hosts = Vec::new();
        for host in https_hosts {
            if hosts.len() == MAX_HOSTS {
                return Err(ManualCaptureError::InvalidPolicy);
            }
            let host = normalize_host(host.as_ref())?;
            if is_loopback_host(&host) {
                return Err(ManualCaptureError::InvalidPolicy);
            }
            hosts.push(host);
        }
        hosts.sort();
        hosts.dedup();
        if hosts.is_empty() {
            return Err(ManualCaptureError::InvalidPolicy);
        }

        let mut allowed = [false; 2];
        for (header_count, header) in allowed_headers.into_iter().enumerate() {
            if header_count == allowed.len() || allowed[header.index()] {
                return Err(ManualCaptureError::InvalidPolicy);
            }
            allowed[header.index()] = true;
        }
        if !allowed.iter().any(|value| *value) {
            return Err(ManualCaptureError::InvalidPolicy);
        }

        Ok(Self {
            https_hosts: hosts,
            loopback_hosts: Vec::new(),
            allowed_headers: allowed,
            forwarded_headers: Vec::new(),
            ignore_url_query: false,
        })
    }

    /// Accepts a captured URL query solely for exact-origin validation, then
    /// removes it before returning the capture.
    ///
    /// This explicit capability supports browser-generated cURL commands whose
    /// fixed provider endpoint contains non-secret query parameters. Providers
    /// must rebuild their own request URL; the captured query is never exposed
    /// or forwarded. Queries remain rejected by default.
    #[must_use]
    pub const fn with_ignored_url_query(mut self) -> Self {
        self.ignore_url_query = true;
        self
    }

    /// Grants forwarding authority for exact non-credential metadata headers.
    ///
    /// Names are canonicalized to lowercase and matched case-insensitively.
    /// Credential, host, proxy, connection, and message-framing headers can
    /// never be granted. Raw non-cURL input remains credential-only.
    ///
    /// # Errors
    ///
    /// Returns [`ManualCaptureError::InvalidPolicy`] for malformed, reserved,
    /// or excessive header names.
    pub fn with_forwarded_headers<Headers, HeaderValue>(
        mut self,
        headers: Headers,
    ) -> Result<Self, ManualCaptureError>
    where
        Headers: IntoIterator<Item = HeaderValue>,
        HeaderValue: AsRef<str>,
    {
        let mut forwarded = Vec::new();
        for header in headers {
            if forwarded.len() == MAX_FORWARDED_HEADERS {
                return Err(ManualCaptureError::InvalidPolicy);
            }
            let header = header.as_ref();
            if !valid_header_name(header) || is_reserved_forwarded_header(header) {
                return Err(ManualCaptureError::InvalidPolicy);
            }
            forwarded.push(header.to_ascii_lowercase());
        }
        forwarded.sort();
        forwarded.dedup();
        self.forwarded_headers = forwarded;
        Ok(self)
    }

    /// Adds one explicitly typed loopback host.
    ///
    /// HTTP is accepted only for hosts granted through this typed seam. HTTPS
    /// remains accepted as well. Any explicit port is permitted because local
    /// test servers conventionally use ephemeral ports.
    ///
    /// # Errors
    ///
    /// Returns [`ManualCaptureError::InvalidPolicy`] if the host bound would be
    /// exceeded.
    pub fn with_loopback_host(
        mut self,
        host: LoopbackCaptureHost,
    ) -> Result<Self, ManualCaptureError> {
        if self.https_hosts.len() + self.loopback_hosts.len() == MAX_HOSTS {
            return Err(ManualCaptureError::InvalidPolicy);
        }
        self.loopback_hosts.push(host.host);
        self.loopback_hosts.sort();
        self.loopback_hosts.dedup();
        Ok(self)
    }

    /// Parses a raw header, cookie value, or bounded cURL capture.
    ///
    /// # Errors
    ///
    /// Returns a stable, secret-free [`ManualCaptureError`] for malformed,
    /// ambiguous, oversized, expanding, file-reading, or unauthorized input.
    pub fn parse(&self, raw: &str) -> Result<ManualCapture, ManualCaptureError> {
        validate_input_bound(raw)?;
        if starts_with_curl_command(raw) {
            self.parse_curl(raw)
        } else {
            self.parse_raw(raw)
        }
    }

    fn parse_raw(&self, raw: &str) -> Result<ManualCapture, ManualCaptureError> {
        validate_no_controls(raw)?;
        let raw = trim_ascii(raw);
        if raw.is_empty() {
            return Err(ManualCaptureError::MissingSecret);
        }

        let (header, value) = if let Some(value) = strip_header_prefix(raw, "cookie") {
            (CaptureHeader::Cookie, value)
        } else if let Some(value) = strip_header_prefix(raw, "authorization") {
            (CaptureHeader::Authorization, value)
        } else {
            (CaptureHeader::Cookie, strip_matching_quotes(raw)?)
        };
        let value = strip_matching_quotes(value)?;
        if !self.allowed_headers[header.index()] {
            return Err(ManualCaptureError::DisallowedHeader);
        }

        let secret = CaptureSecret::new(value, header)?;
        let mut capture = ManualCapture::empty();
        capture.secrets[header.index()] = Some(secret);
        Ok(capture)
    }

    fn parse_curl(&self, raw: &str) -> Result<ManualCapture, ManualCaptureError> {
        let mut tokens = tokenize(raw)?;
        if tokens.first().map(AsRef::as_ref) != Some("curl") {
            return Err(ManualCaptureError::InvalidSyntax);
        }

        let mut capture = ManualCapture::empty();
        let mut url = None;
        let mut header_count = 0_usize;
        let mut positional_only = false;
        let mut index = 1_usize;

        while index < tokens.len() {
            let token = tokens[index].as_str();
            if !positional_only && token == "--" {
                positional_only = true;
                index += 1;
                continue;
            }

            if !positional_only {
                if matches!(token, "-H" | "--header") {
                    let next = take_following(&mut tokens, index)?;
                    header_count = increment_headers(header_count)?;
                    self.capture_header(next, &mut capture)?;
                    index += 2;
                    continue;
                }
                if let Some(value) = token.strip_prefix("--header=") {
                    if value.is_empty() {
                        return Err(ManualCaptureError::InvalidSyntax);
                    }
                    let value = Zeroizing::new(value.to_owned());
                    header_count = increment_headers(header_count)?;
                    self.capture_header(value, &mut capture)?;
                    index += 1;
                    continue;
                }
                if token.starts_with("-H") && token.len() > 2 {
                    let value = Zeroizing::new(token[2..].to_owned());
                    header_count = increment_headers(header_count)?;
                    self.capture_header(value, &mut capture)?;
                    index += 1;
                    continue;
                }

                if matches!(token, "-b" | "--cookie") {
                    let next = take_following(&mut tokens, index)?;
                    header_count = increment_headers(header_count)?;
                    self.capture_cookie(next, &mut capture)?;
                    index += 2;
                    continue;
                }
                if let Some(value) = token.strip_prefix("--cookie=") {
                    if value.is_empty() {
                        return Err(ManualCaptureError::InvalidSyntax);
                    }
                    let value = Zeroizing::new(value.to_owned());
                    header_count = increment_headers(header_count)?;
                    self.capture_cookie(value, &mut capture)?;
                    index += 1;
                    continue;
                }
                if token.starts_with("-b") && token.len() > 2 {
                    let value = Zeroizing::new(token[2..].to_owned());
                    header_count = increment_headers(header_count)?;
                    self.capture_cookie(value, &mut capture)?;
                    index += 1;
                    continue;
                }

                if matches!(token, "--url") {
                    let next = take_following(&mut tokens, index)?;
                    set_url(&mut url, next)?;
                    index += 2;
                    continue;
                }
                if let Some(value) = token.strip_prefix("--url=") {
                    if value.is_empty() {
                        return Err(ManualCaptureError::InvalidSyntax);
                    }
                    set_url(&mut url, Zeroizing::new(value.to_owned()))?;
                    index += 1;
                    continue;
                }

                if is_safe_flag(token) {
                    index += 1;
                    continue;
                }
                if token.starts_with('-') {
                    return Err(ManualCaptureError::UnsafeOption);
                }
            }

            set_url(&mut url, mem::take(&mut tokens[index]))?;
            index += 1;
        }

        if let Some(raw_url) = url {
            capture.url = Some(self.validate_url(raw_url.as_str())?);
        }
        if capture.secrets.iter().all(Option::is_none) {
            return Err(ManualCaptureError::MissingSecret);
        }
        Ok(capture)
    }

    fn capture_header(
        &self,
        mut field: Zeroizing<String>,
        capture: &mut ManualCapture,
    ) -> Result<(), ManualCaptureError> {
        if field.starts_with('@') {
            return Err(ManualCaptureError::UnsafeOption);
        }
        validate_no_controls(field.as_str())?;
        let Some(colon) = field.find(':') else {
            return Err(ManualCaptureError::InvalidSyntax);
        };
        let name = trim_ascii(&field[..colon]);
        if !valid_header_name(name) {
            return Err(ManualCaptureError::InvalidSyntax);
        }
        let header = if name.eq_ignore_ascii_case("cookie") {
            Some(CaptureHeader::Cookie)
        } else if name.eq_ignore_ascii_case("authorization") {
            Some(CaptureHeader::Authorization)
        } else {
            None
        };

        if let Some(header) = header {
            if !self.allowed_headers[header.index()] {
                return Ok(());
            }
            if capture.secrets[header.index()].is_some() {
                return Err(ManualCaptureError::DuplicateSecret);
            }
            field.drain(..=colon);
            trim_zeroizing(&mut field);
            capture.secrets[header.index()] = Some(CaptureSecret::from_zeroizing(field, header)?);
            return Ok(());
        }

        let normalized_name = name.to_ascii_lowercase();
        if self
            .forwarded_headers
            .binary_search(&normalized_name)
            .is_err()
        {
            return Ok(());
        }
        field.drain(..=colon);
        trim_zeroizing(&mut field);
        capture.insert_forwarded(normalized_name, field)?;
        Ok(())
    }

    fn capture_cookie(
        &self,
        mut value: Zeroizing<String>,
        capture: &mut ManualCapture,
    ) -> Result<(), ManualCaptureError> {
        if value.starts_with('@') {
            return Err(ManualCaptureError::UnsafeOption);
        }
        if !self.allowed_headers[CaptureHeader::Cookie.index()] {
            return Ok(());
        }
        if capture.secrets[CaptureHeader::Cookie.index()].is_some() {
            return Err(ManualCaptureError::DuplicateSecret);
        }
        trim_zeroizing(&mut value);
        capture.secrets[CaptureHeader::Cookie.index()] =
            Some(CaptureSecret::from_zeroizing(value, CaptureHeader::Cookie)?);
        Ok(())
    }

    fn validate_url(&self, raw: &str) -> Result<Url, ManualCaptureError> {
        validate_no_controls(raw)?;
        let mut url = Url::parse(raw).map_err(|_| ManualCaptureError::DisallowedUrl)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || (url.query().is_some() && !self.ignore_url_query)
            || url.fragment().is_some()
        {
            return Err(ManualCaptureError::DisallowedUrl);
        }
        let host = canonical_url_host(&url).ok_or(ManualCaptureError::DisallowedUrl)?;

        if self.loopback_hosts.iter().any(|allowed| allowed == &host) {
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ManualCaptureError::DisallowedUrl);
            }
            url.set_query(None);
            return Ok(url);
        }
        if url.scheme() != "https"
            || url.port_or_known_default() != Some(443)
            || !self.https_hosts.iter().any(|allowed| allowed == &host)
        {
            return Err(ManualCaptureError::DisallowedUrl);
        }
        url.set_query(None);
        Ok(url)
    }
}

impl Debug for ManualCapturePolicy {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManualCapturePolicy")
            .field("https_host_count", &self.https_hosts.len())
            .field("loopback_host_count", &self.loopback_hosts.len())
            .field("allowed_headers", &"<redacted>")
            .field("forwarded_header_count", &self.forwarded_headers.len())
            .field("ignores_url_query", &self.ignore_url_query)
            .finish()
    }
}

/// One successfully parsed, policy-bound manual credential capture.
pub struct ManualCapture {
    secrets: [Option<CaptureSecret>; 2],
    forwarded_headers: Vec<ForwardedHeader>,
    url: Option<Url>,
}

impl ManualCapture {
    const fn empty() -> Self {
        Self {
            secrets: [None, None],
            forwarded_headers: Vec::new(),
            url: None,
        }
    }

    /// Returns an extracted secret only for the requested header class.
    #[must_use]
    pub fn header(&self, header: CaptureHeader) -> Option<&str> {
        self.secrets[header.index()]
            .as_ref()
            .map(CaptureSecret::expose)
    }

    /// Returns the validated captured URL, when the input supplied one.
    #[must_use]
    pub const fn url(&self) -> Option<&Url> {
        self.url.as_ref()
    }

    /// Iterates the exact policy-allowed browser metadata headers.
    ///
    /// Names are lowercase and sorted for deterministic request construction.
    /// Values remain owned by zeroizing allocations inside the capture.
    #[must_use]
    pub fn forwarded_headers(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.forwarded_headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
    }

    fn insert_forwarded(
        &mut self,
        name: String,
        value: Zeroizing<String>,
    ) -> Result<(), ManualCaptureError> {
        if value.is_empty() || value.len() > MAX_FORWARDED_VALUE_BYTES {
            return Err(ManualCaptureError::InvalidSecret);
        }
        validate_no_controls(value.as_str())?;
        match self
            .forwarded_headers
            .binary_search_by(|header| header.name.cmp(&name))
        {
            Ok(index) => {
                if self.forwarded_headers[index].value.as_str() != value.as_str() {
                    return Err(ManualCaptureError::ConflictingHeader);
                }
            }
            Err(index) => self
                .forwarded_headers
                .insert(index, ForwardedHeader { name, value }),
        }
        Ok(())
    }
}

impl Debug for ManualCapture {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManualCapture")
            .field("has_cookie", &self.secrets[0].is_some())
            .field("has_authorization", &self.secrets[1].is_some())
            .field("forwarded_header_count", &self.forwarded_headers.len())
            .field("has_url", &self.url.is_some())
            .finish()
    }
}

struct ForwardedHeader {
    name: String,
    value: Zeroizing<String>,
}

/// A bounded secret that zeroizes its owned allocation on drop.
pub struct CaptureSecret {
    value: Zeroizing<String>,
}

impl CaptureSecret {
    fn new(value: &str, header: CaptureHeader) -> Result<Self, ManualCaptureError> {
        Self::from_zeroizing(Zeroizing::new(value.to_owned()), header)
    }

    fn from_zeroizing(
        mut value: Zeroizing<String>,
        header: CaptureHeader,
    ) -> Result<Self, ManualCaptureError> {
        trim_zeroizing(&mut value);
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(ManualCaptureError::InvalidSecret);
        }
        validate_no_controls(value.as_str())?;
        match header {
            CaptureHeader::Cookie if !valid_cookie(value.as_str()) => {
                return Err(ManualCaptureError::InvalidSecret);
            }
            _ => {}
        }
        Ok(Self { value })
    }

    /// Exposes the credential to the provider request builder.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.as_str()
    }
}

impl Debug for CaptureSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CaptureSecret(<redacted>)")
    }
}

/// Stable parser failures which never retain or display input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ManualCaptureError {
    /// The supplied capture exceeds the fixed byte bound.
    #[error("manual capture exceeds its size bound")]
    InputTooLarge,
    /// The policy contains malformed, unsafe, empty, or excessive authority.
    #[error("manual capture policy is invalid")]
    InvalidPolicy,
    /// Shell-like quoting or argument structure is malformed or excessive.
    #[error("manual capture syntax is invalid")]
    InvalidSyntax,
    /// Expansion or shell-control syntax was present.
    #[error("manual capture contains unsafe shell syntax")]
    UnsafeSyntax,
    /// An option capable of changing, reading, or writing request data was present.
    #[error("manual capture contains an unsupported option")]
    UnsafeOption,
    /// The shell-like token count exceeds the fixed bound.
    #[error("manual capture exceeds its token bound")]
    TooManyTokens,
    /// The header count exceeds the fixed bound.
    #[error("manual capture exceeds its header bound")]
    TooManyHeaders,
    /// A captured secret is empty, malformed, or oversized.
    #[error("manual capture credential is invalid")]
    InvalidSecret,
    /// More than one value was supplied for the same accepted credential class.
    #[error("manual capture contains duplicate credentials")]
    DuplicateSecret,
    /// A forwarded metadata header was repeated with a different value.
    #[error("manual capture contains conflicting forwarded headers")]
    ConflictingHeader,
    /// Raw header text used a credential class the policy does not accept.
    #[error("manual capture header is not allowed")]
    DisallowedHeader,
    /// A URL was malformed or outside the policy's exact host authority.
    #[error("manual capture URL is not allowed")]
    DisallowedUrl,
    /// No accepted credential was found.
    #[error("manual capture does not contain an accepted credential")]
    MissingSecret,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    Unquoted,
    Single,
    Double,
    AnsiSingle,
}

fn tokenize(raw: &str) -> Result<Vec<Zeroizing<String>>, ManualCaptureError> {
    validate_input_bound(raw)?;
    let mut tokens = Vec::new();
    let mut token = Zeroizing::new(String::new());
    let mut state = QuoteState::Unquoted;
    let mut token_started = false;
    let mut transitions = 0_usize;
    let mut chars = raw.chars().peekable();

    while let Some(character) = chars.next() {
        match state {
            QuoteState::Unquoted => match character {
                value if value.is_ascii_whitespace() => {
                    if value == '\r' && chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    finish_token(&mut tokens, &mut token, &mut token_started)?;
                }
                '\'' => {
                    transition(&mut transitions)?;
                    state = QuoteState::Single;
                    token_started = true;
                }
                '"' => {
                    transition(&mut transitions)?;
                    state = QuoteState::Double;
                    token_started = true;
                }
                '$' if chars.peek() == Some(&'\'') => {
                    chars.next();
                    transition(&mut transitions)?;
                    state = QuoteState::AnsiSingle;
                    token_started = true;
                }
                '$' | '`' | '|' | '&' | ';' | '<' | '>' | '(' | ')' | '#' | '*' | '?' | '['
                | ']' | '{' | '}' | '~' => return Err(ManualCaptureError::UnsafeSyntax),
                '\\' => {
                    let escaped = chars.next().ok_or(ManualCaptureError::InvalidSyntax)?;
                    if escaped == '\r' {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                    } else if escaped != '\n' {
                        push_char(&mut token, escaped)?;
                        token_started = true;
                    }
                }
                value if value.is_control() => return Err(ManualCaptureError::UnsafeSyntax),
                value => {
                    push_char(&mut token, value)?;
                    token_started = true;
                }
            },
            QuoteState::Single => match character {
                '\'' => {
                    transition(&mut transitions)?;
                    state = QuoteState::Unquoted;
                }
                value if value.is_control() => return Err(ManualCaptureError::UnsafeSyntax),
                value => push_char(&mut token, value)?,
            },
            QuoteState::Double => match character {
                '"' => {
                    transition(&mut transitions)?;
                    state = QuoteState::Unquoted;
                }
                '$' | '`' => return Err(ManualCaptureError::UnsafeSyntax),
                '\\' => {
                    let escaped = chars.next().ok_or(ManualCaptureError::InvalidSyntax)?;
                    if escaped == '\r' {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                    } else if escaped != '\n' {
                        if !matches!(escaped, '"' | '\\') {
                            return Err(ManualCaptureError::UnsafeSyntax);
                        }
                        push_char(&mut token, escaped)?;
                    }
                }
                value if value.is_control() => return Err(ManualCaptureError::UnsafeSyntax),
                value => push_char(&mut token, value)?,
            },
            QuoteState::AnsiSingle => consume_ansi_character(
                character,
                &mut chars,
                &mut token,
                &mut state,
                &mut transitions,
            )?,
        }
    }

    if state != QuoteState::Unquoted {
        return Err(ManualCaptureError::InvalidSyntax);
    }
    finish_token(&mut tokens, &mut token, &mut token_started)?;
    Ok(tokens)
}

fn consume_ansi_character(
    character: char,
    chars: &mut impl Iterator<Item = char>,
    token: &mut String,
    state: &mut QuoteState,
    transitions: &mut usize,
) -> Result<(), ManualCaptureError> {
    match character {
        '\'' => {
            transition(transitions)?;
            *state = QuoteState::Unquoted;
        }
        '\\' => {
            let escaped = chars.next().ok_or(ManualCaptureError::InvalidSyntax)?;
            if !matches!(escaped, '\\' | '\'' | '"') {
                return Err(ManualCaptureError::UnsafeSyntax);
            }
            push_char(token, escaped)?;
        }
        value if value.is_control() => return Err(ManualCaptureError::UnsafeSyntax),
        value => push_char(token, value)?,
    }
    Ok(())
}

fn finish_token(
    tokens: &mut Vec<Zeroizing<String>>,
    token: &mut Zeroizing<String>,
    started: &mut bool,
) -> Result<(), ManualCaptureError> {
    if !*started {
        return Ok(());
    }
    if tokens.len() == MAX_TOKENS {
        return Err(ManualCaptureError::TooManyTokens);
    }
    tokens.push(mem::take(token));
    *started = false;
    Ok(())
}

fn transition(count: &mut usize) -> Result<(), ManualCaptureError> {
    *count += 1;
    if *count > MAX_QUOTE_TRANSITIONS {
        return Err(ManualCaptureError::InvalidSyntax);
    }
    Ok(())
}

fn push_char(token: &mut String, value: char) -> Result<(), ManualCaptureError> {
    if token.len() + value.len_utf8() > MAX_TOKEN_BYTES {
        return Err(ManualCaptureError::InputTooLarge);
    }
    token.push(value);
    Ok(())
}

fn take_following(
    tokens: &mut [Zeroizing<String>],
    index: usize,
) -> Result<Zeroizing<String>, ManualCaptureError> {
    let following = tokens
        .get_mut(index + 1)
        .ok_or(ManualCaptureError::InvalidSyntax)?;
    if following.starts_with('-') {
        return Err(ManualCaptureError::InvalidSyntax);
    }
    Ok(mem::take(following))
}

fn set_url(
    destination: &mut Option<Zeroizing<String>>,
    value: Zeroizing<String>,
) -> Result<(), ManualCaptureError> {
    if value.is_empty() || value.starts_with('@') || destination.is_some() {
        return Err(ManualCaptureError::InvalidSyntax);
    }
    *destination = Some(value);
    Ok(())
}

fn increment_headers(count: usize) -> Result<usize, ManualCaptureError> {
    let next = count + 1;
    if next > MAX_HEADERS {
        return Err(ManualCaptureError::TooManyHeaders);
    }
    Ok(next)
}

fn is_safe_flag(token: &str) -> bool {
    matches!(
        token,
        "--compressed"
            | "--fail"
            | "--fail-with-body"
            | "--globoff"
            | "--no-progress-meter"
            | "--show-error"
            | "--silent"
    ) || token.strip_prefix('-').is_some_and(|flags| {
        !flags.is_empty()
            && flags
                .bytes()
                .all(|value| matches!(value, b'f' | b'g' | b's' | b'S'))
    })
}

fn validate_input_bound(raw: &str) -> Result<(), ManualCaptureError> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(ManualCaptureError::InputTooLarge);
    }
    Ok(())
}

fn validate_no_controls(raw: &str) -> Result<(), ManualCaptureError> {
    if raw.chars().any(char::is_control) {
        return Err(ManualCaptureError::UnsafeSyntax);
    }
    Ok(())
}

fn starts_with_curl_command(raw: &str) -> bool {
    let raw = raw.trim_start_matches(|character: char| character.is_whitespace());
    raw.strip_prefix("curl")
        .and_then(|rest| rest.chars().next())
        .is_some_and(char::is_whitespace)
}

fn strip_header_prefix<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let (candidate, value) = raw.split_once(':')?;
    candidate
        .trim()
        .eq_ignore_ascii_case(name)
        .then(|| trim_ascii(value))
}

fn strip_matching_quotes(raw: &str) -> Result<&str, ManualCaptureError> {
    if raw.len() >= 2
        && ((raw.starts_with('\'') && raw.ends_with('\''))
            || (raw.starts_with('"') && raw.ends_with('"')))
    {
        return Ok(trim_ascii(&raw[1..raw.len() - 1]));
    }
    if raw.starts_with(['\'', '"']) || raw.ends_with(['\'', '"']) {
        return Err(ManualCaptureError::InvalidSyntax);
    }
    Ok(raw)
}

fn trim_ascii(raw: &str) -> &str {
    raw.trim_matches(|value: char| value.is_ascii_whitespace())
}

fn trim_zeroizing(value: &mut Zeroizing<String>) {
    let leading = value.len()
        - value
            .trim_start_matches(|character: char| character.is_ascii_whitespace())
            .len();
    if leading > 0 {
        value.drain(..leading);
    }
    let trimmed_len = value
        .trim_end_matches(|character: char| character.is_ascii_whitespace())
        .len();
    value.truncate(trimmed_len);
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HEADER_NAME_BYTES
        && name.bytes().all(|value| {
            value.is_ascii_alphanumeric()
                || matches!(
                    value,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_reserved_forwarded_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "host"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "www-authenticate"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-access-token"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

fn valid_cookie(value: &str) -> bool {
    let mut found = false;
    for pair in value.split(';') {
        let pair = trim_ascii(pair);
        let Some((name, _value)) = pair.split_once('=') else {
            return false;
        };
        let name = trim_ascii(name);
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return false;
        }
        found = true;
    }
    found
}

fn normalize_host(raw: &str) -> Result<String, ManualCaptureError> {
    if raw.is_empty() || raw.len() > 253 || raw.chars().any(char::is_control) || raw.contains('*') {
        return Err(ManualCaptureError::InvalidPolicy);
    }
    let candidate = format!("https://{raw}/");
    let url = Url::parse(&candidate).map_err(|_| ManualCaptureError::InvalidPolicy)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ManualCaptureError::InvalidPolicy);
    }
    let (host, reconstructed) = match url.host() {
        Some(Host::Domain(domain)) => {
            let host = domain.to_ascii_lowercase();
            (host.clone(), host)
        }
        Some(Host::Ipv4(address)) => {
            let host = address.to_string();
            (host.clone(), host)
        }
        Some(Host::Ipv6(address)) => {
            let host = address.to_string();
            let reconstructed = format!("[{host}]");
            (host, reconstructed)
        }
        None => return Err(ManualCaptureError::InvalidPolicy),
    };
    if !raw.eq_ignore_ascii_case(&reconstructed) {
        return Err(ManualCaptureError::InvalidPolicy);
    }
    Ok(host)
}

fn canonical_url_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(domain) => Some(domain.to_ascii_lowercase()),
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|value| value.is_loopback())
        || host
            .parse::<Ipv6Addr>()
            .is_ok_and(|value| value.is_loopback())
}
