//! Deterministic, bounded request signing for cloud-provider APIs.
//!
//! This module deliberately owns the bytes that are signed. Callers cannot sign
//! one body and accidentally send another, and neither credentials nor signed
//! header values are included in `Debug` or error output.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use hmac::{Hmac, Mac};
use reqwest::Method;
use reqwest::header::{HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::endpoint::{EndpointClass, ValidatedEndpoint};

const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_HEADER_COUNT: usize = 64;
const MAX_HEADER_VALUE_BYTES: usize = 16 * 1024;
const MAX_TOTAL_HEADER_BYTES: usize = 64 * 1024;
const MAX_ACCESS_KEY_BYTES: usize = 256;
const MAX_SECRET_KEY_BYTES: usize = 4 * 1024;
const MAX_SESSION_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SCOPE_COMPONENT_BYTES: usize = 128;

const AWS_ALGORITHM: &str = "AWS4-HMAC-SHA256";
const AWS_TERMINATOR: &str = "aws4_request";
const VOLCENGINE_ALGORITHM: &str = "HMAC-SHA256";
const VOLCENGINE_SERVICE: &str = "ark";
const VOLCENGINE_TERMINATOR: &str = "request";
const VOLCENGINE_SIGNED_HEADERS: &str = "content-type;host;x-content-sha256;x-date";
const DEFAULT_VOLCENGINE_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

type HmacSha256 = Hmac<Sha256>;

/// A non-sensitive classification of invalid signing input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigningError {
    #[error("cloud signing credential is missing, malformed, or too large")]
    InvalidCredential,
    #[error("cloud signing scope is missing, malformed, or too large")]
    InvalidScope,
    #[error("cloud signing URL is unsafe, malformed, or too large")]
    InvalidUrl,
    #[error("cloud signing request method is invalid")]
    InvalidMethod,
    #[error("cloud signing request body exceeds its size limit")]
    BodyTooLarge,
    #[error("cloud signing request headers are malformed or exceed their limits")]
    InvalidHeaders,
    #[error("cloud signing timestamp must be UTC and use a four-digit year")]
    InvalidTimestamp,
    #[error("cloud signing operation failed")]
    SigningFailed,
}

/// An AWS access-key credential, zeroized on drop and redacted in diagnostics.
#[derive(Clone)]
pub struct AwsCredentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl AwsCredentials {
    /// Creates a bounded AWS access-key credential.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::InvalidCredential`] when a required value is
    /// empty, contains a control character, or exceeds its size limit.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<impl Into<String>>,
    ) -> Result<Self, SigningError> {
        let access_key_id = Zeroizing::new(access_key_id.into());
        let secret_access_key = Zeroizing::new(secret_access_key.into());
        let session_token = session_token.map(|value| Zeroizing::new(value.into()));

        validate_credential(&access_key_id, MAX_ACCESS_KEY_BYTES)?;
        validate_credential(&secret_access_key, MAX_SECRET_KEY_BYTES)?;
        if let Some(token) = &session_token {
            validate_credential(token, MAX_SESSION_TOKEN_BYTES)?;
        }

        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCredentials")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A Volcengine access-key credential, zeroized on drop and redacted in diagnostics.
#[derive(Clone)]
pub struct VolcengineCredentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    region: String,
}

impl VolcengineCredentials {
    /// Creates a bounded Volcengine access-key credential and signing region.
    ///
    /// # Errors
    ///
    /// Returns an error when a credential or scope component is empty,
    /// malformed, or exceeds its size limit.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
    ) -> Result<Self, SigningError> {
        let access_key_id = Zeroizing::new(access_key_id.into());
        let secret_access_key = Zeroizing::new(secret_access_key.into());
        let region = region.into();

        validate_credential(&access_key_id, MAX_ACCESS_KEY_BYTES)?;
        validate_credential(&secret_access_key, MAX_SECRET_KEY_BYTES)?;
        validate_scope_component(&region)?;

        Ok(Self {
            access_key_id,
            secret_access_key,
            region,
        })
    }

    /// Returns the validated signing region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
}

impl fmt::Debug for VolcengineCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VolcengineCredentials")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .finish()
    }
}

/// A normalized HTTP header. Its value is zeroized and always redacted in `Debug`.
#[derive(Clone)]
pub struct SignedHeader {
    name: HeaderName,
    value: Zeroizing<String>,
}

impl SignedHeader {
    fn new(name: HeaderName, value: String) -> Result<Self, SigningError> {
        let value = Zeroizing::new(value);
        if value.len() > MAX_HEADER_VALUE_BYTES || !is_safe_header_value(&value) {
            return Err(SigningError::InvalidHeaders);
        }
        let value = fold_header_whitespace(&value);
        HeaderValue::from_str(&value).map_err(|_| SigningError::InvalidHeaders)?;
        Ok(Self {
            name,
            value: Zeroizing::new(value),
        })
    }

    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Returns the validated value for insertion into an HTTP request.
    ///
    /// The caller must continue to treat security-token and authorization values
    /// as sensitive after this method exposes them.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Converts the validated value into a sensitive HTTP header value.
    ///
    /// # Panics
    ///
    /// This can only panic if the private constructor's header validation
    /// invariant is broken.
    #[must_use]
    pub fn to_header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_str(&self.value)
            .expect("signed headers are validated when constructed");
        value.set_sensitive(true);
        value
    }
}

impl fmt::Debug for SignedHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The exact method, URL, headers, and body to canonicalize.
#[derive(Clone)]
pub struct SigningRequest {
    method: Method,
    url: Url,
    headers: Vec<SignedHeader>,
    body: Zeroizing<Vec<u8>>,
    total_header_bytes: usize,
}

impl SigningRequest {
    /// Creates the exact bounded request whose bytes will be signed.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe URLs or methods, or when the body exceeds
    /// the hard request limit.
    pub fn new(method: Method, url: Url, body: impl Into<Vec<u8>>) -> Result<Self, SigningError> {
        Self::new_inner(method, url, body, false)
    }

    /// Creates a request from an endpoint-policy proof. This is the sole path
    /// that permits plain HTTP, and only for an already validated loopback
    /// development endpoint.
    pub(crate) fn for_validated_endpoint(
        method: Method,
        endpoint: &ValidatedEndpoint,
        body: impl Into<Vec<u8>>,
    ) -> Result<Self, SigningError> {
        let permits_loopback_http = endpoint.class() == EndpointClass::LoopbackDevelopment
            && endpoint.url().scheme() == "http";
        Self::new_inner(method, endpoint.url().clone(), body, permits_loopback_http)
    }

    fn new_inner(
        method: Method,
        url: Url,
        body: impl Into<Vec<u8>>,
        permits_loopback_http: bool,
    ) -> Result<Self, SigningError> {
        validate_method(&method)?;
        validate_url(&url, permits_loopback_http)?;
        let body = Zeroizing::new(body.into());
        if body.len() > MAX_BODY_BYTES {
            return Err(SigningError::BodyTooLarge);
        }
        Ok(Self {
            method,
            url,
            headers: Vec::new(),
            body,
            total_header_bytes: 0,
        })
    }

    /// Adds a bounded, normalized header to the canonical request.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::InvalidHeaders`] for malformed, reserved, or
    /// oversized header input.
    pub fn with_header(mut self, name: &str, value: &str) -> Result<Self, SigningError> {
        if self.headers.len() >= MAX_HEADER_COUNT {
            return Err(SigningError::InvalidHeaders);
        }
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| SigningError::InvalidHeaders)?;
        if name == reqwest::header::AUTHORIZATION || name == reqwest::header::HOST {
            return Err(SigningError::InvalidHeaders);
        }
        let next_total = self
            .total_header_bytes
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(SigningError::InvalidHeaders)?;
        if next_total > MAX_TOTAL_HEADER_BYTES {
            return Err(SigningError::InvalidHeaders);
        }
        self.headers
            .push(SignedHeader::new(name, value.to_owned())?);
        self.total_header_bytes = next_total;
        Ok(self)
    }

    /// Returns the exact HTTP method to sign and send.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the exact URL to sign and send.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the exact body bytes to sign and send.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for SigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("headers", &self.headers)
            .field(
                "body",
                &format_args!("<redacted; {} bytes>", self.body.len()),
            )
            .finish_non_exhaustive()
    }
}

/// A canonicalized request and its signer-produced headers.
#[derive(Clone)]
pub struct SignedRequest {
    method: Method,
    url: Url,
    headers: Vec<SignedHeader>,
    body: Zeroizing<Vec<u8>>,
    canonical_request_hash: [u8; 32],
}

impl SignedRequest {
    /// Returns the signed HTTP method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the signed URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the canonical headers, including signer-produced headers.
    #[must_use]
    pub fn headers(&self) -> &[SignedHeader] {
        &self.headers
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.as_str().eq_ignore_ascii_case(name))
            .map(SignedHeader::value)
    }

    /// Returns the body bytes covered by the signature.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the canonical request hash for known-answer verification.
    #[must_use]
    pub fn canonical_request_hash_hex(&self) -> String {
        hex(&self.canonical_request_hash)
    }
}

impl fmt::Debug for SignedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|header| header.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "body",
                &format_args!("<redacted; {} bytes>", self.body.len()),
            )
            .field("canonical_request_hash", &"<redacted>")
            .finish()
    }
}

/// AWS Signature Version 4 signer with a fixed region and service scope.
#[derive(Clone, Debug)]
pub struct AwsSigV4Signer {
    region: String,
    service: String,
}

impl AwsSigV4Signer {
    /// Creates a signer for a validated AWS region and service.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::InvalidScope`] when either scope component is
    /// empty, malformed, or exceeds its size limit.
    pub fn new(
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, SigningError> {
        let region = region.into();
        let service = service.into();
        validate_scope_component(&region)?;
        validate_scope_component(&service)?;
        Ok(Self { region, service })
    }

    /// Signs a fully constructed request at the supplied UTC timestamp.
    ///
    /// # Errors
    ///
    /// Returns a classified signing error when request canonicalization,
    /// credential derivation, or timestamp formatting fails.
    pub fn sign(
        &self,
        request: SigningRequest,
        credentials: &AwsCredentials,
        timestamp: OffsetDateTime,
    ) -> Result<SignedRequest, SigningError> {
        let (date_stamp, timestamp) = format_timestamp(timestamp)?;
        reject_managed_headers(
            &request.headers,
            &["x-amz-content-sha256", "x-amz-date", "x-amz-security-token"],
        )?;

        let payload_hash = sha256(request.body());
        let payload_hash_hex = hex(&payload_hash);
        let host = canonical_host(request.url())?;
        let mut headers = request.headers;
        headers.push(SignedHeader::new(HeaderName::from_static("host"), host)?);
        headers.push(SignedHeader::new(
            HeaderName::from_static("x-amz-content-sha256"),
            payload_hash_hex,
        )?);
        headers.push(SignedHeader::new(
            HeaderName::from_static("x-amz-date"),
            timestamp.clone(),
        )?);
        if let Some(token) = &credentials.session_token {
            headers.push(SignedHeader::new(
                HeaderName::from_static("x-amz-security-token"),
                token.to_string(),
            )?);
        }
        sort_headers(&mut headers);

        let canonical_headers = canonical_headers(&headers)?;
        let canonical_uri = canonical_uri(&request.url)?;
        let canonical_query = canonical_query(&request.url)?;
        let mut canonical_request = Zeroizing::new(String::new());
        write!(
            canonical_request,
            "{}\n{canonical_uri}\n{canonical_query}\n{}\n{}\n{}",
            request.method.as_str(),
            canonical_headers.block.as_str(),
            canonical_headers.names,
            hex(&payload_hash),
        )
        .map_err(|_| SigningError::SigningFailed)?;
        let canonical_request_hash = sha256(canonical_request.as_bytes());
        let credential_scope = format!(
            "{date_stamp}/{}/{}/{AWS_TERMINATOR}",
            self.region, self.service
        );
        let string_to_sign = format!(
            "{AWS_ALGORITHM}\n{timestamp}\n{credential_scope}\n{}",
            hex(&canonical_request_hash)
        );
        let signature = aws_signature(
            credentials.secret_access_key.as_bytes(),
            &date_stamp,
            &self.region,
            &self.service,
            string_to_sign.as_bytes(),
        )?;
        let signature_hex = Zeroizing::new(hex(&signature[..]));
        let authorization = Zeroizing::new(format!(
            "{AWS_ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={}, Signature={}",
            credentials.access_key_id.as_str(),
            canonical_headers.names,
            signature_hex.as_str()
        ));
        headers.push(SignedHeader::new(
            HeaderName::from_static("authorization"),
            authorization.to_string(),
        )?);
        sort_headers(&mut headers);
        validate_output_headers(&headers)?;

        Ok(SignedRequest {
            method: request.method,
            url: request.url,
            headers,
            body: request.body,
            canonical_request_hash,
        })
    }
}

/// Volcengine's V4 HMAC signer for the fixed Ark service.
#[derive(Clone, Copy, Debug, Default)]
pub struct VolcengineV4Signer;

impl VolcengineV4Signer {
    /// Signs a fully constructed Volcengine request at the supplied UTC timestamp.
    ///
    /// # Errors
    ///
    /// Returns a classified signing error when request canonicalization,
    /// credential derivation, or timestamp formatting fails.
    pub fn sign(
        request: SigningRequest,
        credentials: &VolcengineCredentials,
        timestamp: OffsetDateTime,
    ) -> Result<SignedRequest, SigningError> {
        let (date_stamp, timestamp) = format_timestamp(timestamp)?;
        reject_managed_headers(&request.headers, &["x-content-sha256", "x-date"])?;
        if request
            .headers
            .iter()
            .filter(|header| header.name == reqwest::header::CONTENT_TYPE)
            .count()
            > 1
        {
            return Err(SigningError::InvalidHeaders);
        }

        let payload_hash = sha256(request.body());
        let payload_hash_hex = hex(&payload_hash);
        let host = canonical_host(request.url())?;
        let content_type = request
            .headers
            .iter()
            .find(|header| header.name == reqwest::header::CONTENT_TYPE)
            .map_or(DEFAULT_VOLCENGINE_CONTENT_TYPE, SignedHeader::value);
        if content_type.is_empty() {
            return Err(SigningError::InvalidHeaders);
        }

        let canonical_uri = canonical_uri(&request.url)?;
        let canonical_query = canonical_query(&request.url)?;
        let mut canonical_request = Zeroizing::new(String::new());
        write!(
            canonical_request,
            "{}\n{canonical_uri}\n{canonical_query}\ncontent-type:{content_type}\nhost:{host}\nx-content-sha256:{payload_hash_hex}\nx-date:{timestamp}\n\n{VOLCENGINE_SIGNED_HEADERS}\n{payload_hash_hex}",
            request.method.as_str(),
        )
        .map_err(|_| SigningError::SigningFailed)?;
        let canonical_request_hash = sha256(canonical_request.as_bytes());
        let credential_scope = format!(
            "{date_stamp}/{}/{VOLCENGINE_SERVICE}/{VOLCENGINE_TERMINATOR}",
            credentials.region
        );
        let string_to_sign = format!(
            "{VOLCENGINE_ALGORITHM}\n{timestamp}\n{credential_scope}\n{}",
            hex(&canonical_request_hash)
        );
        let signature = volcengine_signature(
            credentials.secret_access_key.as_bytes(),
            &date_stamp,
            &credentials.region,
            string_to_sign.as_bytes(),
        )?;
        let signature_hex = Zeroizing::new(hex(&signature[..]));
        let authorization = Zeroizing::new(format!(
            "{VOLCENGINE_ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={VOLCENGINE_SIGNED_HEADERS}, Signature={}",
            credentials.access_key_id.as_str(),
            signature_hex.as_str()
        ));

        let mut headers = request.headers;
        if !headers
            .iter()
            .any(|header| header.name == reqwest::header::CONTENT_TYPE)
        {
            headers.push(SignedHeader::new(
                HeaderName::from_static("content-type"),
                DEFAULT_VOLCENGINE_CONTENT_TYPE.to_owned(),
            )?);
        }
        headers.push(SignedHeader::new(HeaderName::from_static("host"), host)?);
        headers.push(SignedHeader::new(
            HeaderName::from_static("x-content-sha256"),
            payload_hash_hex,
        )?);
        headers.push(SignedHeader::new(
            HeaderName::from_static("x-date"),
            timestamp,
        )?);
        headers.push(SignedHeader::new(
            HeaderName::from_static("authorization"),
            authorization.to_string(),
        )?);
        sort_headers(&mut headers);
        validate_output_headers(&headers)?;

        Ok(SignedRequest {
            method: request.method,
            url: request.url,
            headers,
            body: request.body,
            canonical_request_hash,
        })
    }
}

struct CanonicalHeaders {
    block: Zeroizing<String>,
    names: String,
}

fn canonical_headers(headers: &[SignedHeader]) -> Result<CanonicalHeaders, SigningError> {
    let mut grouped: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for header in headers {
        grouped
            .entry(header.name.as_str())
            .or_default()
            .push(header.value());
    }
    if grouped.is_empty() {
        return Err(SigningError::InvalidHeaders);
    }

    let names = grouped.keys().copied().collect::<Vec<_>>().join(";");
    let mut block = Zeroizing::new(String::new());
    for (name, values) in grouped {
        write!(block, "{name}:").map_err(|_| SigningError::SigningFailed)?;
        for (index, value) in values.into_iter().enumerate() {
            if index > 0 {
                block.push(',');
            }
            block.push_str(value);
        }
        block.push('\n');
    }
    Ok(CanonicalHeaders { block, names })
}

fn aws_signature(
    secret: &[u8],
    date_stamp: &str,
    region: &str,
    service: &str,
    string_to_sign: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SigningError> {
    let mut initial_key = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    initial_key.extend_from_slice(b"AWS4");
    initial_key.extend_from_slice(secret);
    let date_key = hmac_sha256(&initial_key, date_stamp.as_bytes())?;
    let region_key = hmac_sha256(&date_key[..], region.as_bytes())?;
    let service_key = hmac_sha256(&region_key[..], service.as_bytes())?;
    let signing_key = hmac_sha256(&service_key[..], AWS_TERMINATOR.as_bytes())?;
    hmac_sha256(&signing_key[..], string_to_sign)
}

fn volcengine_signature(
    secret: &[u8],
    date_stamp: &str,
    region: &str,
    string_to_sign: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SigningError> {
    let date_key = hmac_sha256(secret, date_stamp.as_bytes())?;
    let region_key = hmac_sha256(&date_key[..], region.as_bytes())?;
    let service_key = hmac_sha256(&region_key[..], VOLCENGINE_SERVICE.as_bytes())?;
    let signing_key = hmac_sha256(&service_key[..], VOLCENGINE_TERMINATOR.as_bytes())?;
    hmac_sha256(&signing_key[..], string_to_sign)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Zeroizing<[u8; 32]>, SigningError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| SigningError::SigningFailed)?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0_u8; 32]);
    result.copy_from_slice(&digest);
    Ok(result)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn validate_credential(value: &str, maximum: usize) -> Result<(), SigningError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(SigningError::InvalidCredential);
    }
    Ok(())
}

fn validate_scope_component(value: &str) -> Result<(), SigningError> {
    if value.is_empty()
        || value.len() > MAX_SCOPE_COMPONENT_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(SigningError::InvalidScope);
    }
    Ok(())
}

fn validate_method(method: &Method) -> Result<(), SigningError> {
    let value = method.as_str();
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphabetic()
                || byte.is_ascii_digit()
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
        return Err(SigningError::InvalidMethod);
    }
    Ok(())
}

fn validate_output_headers(headers: &[SignedHeader]) -> Result<(), SigningError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(SigningError::InvalidHeaders);
    }
    let total = headers.iter().try_fold(0_usize, |size, header| {
        size.checked_add(header.name.as_str().len())?
            .checked_add(header.value.len())
    });
    if total.is_none_or(|size| size > MAX_TOTAL_HEADER_BYTES) {
        return Err(SigningError::InvalidHeaders);
    }
    Ok(())
}

fn validate_url(url: &Url, permits_loopback_http: bool) -> Result<(), SigningError> {
    let scheme_is_allowed =
        url.scheme() == "https" || (permits_loopback_http && url.scheme() == "http");
    if url.as_str().len() > MAX_URL_BYTES
        || !scheme_is_allowed
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(SigningError::InvalidUrl);
    }
    canonical_host(url)?;
    canonical_uri(url)?;
    canonical_query(url)?;
    Ok(())
}

fn is_safe_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
}

fn fold_header_whitespace(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn reject_managed_headers(headers: &[SignedHeader], managed: &[&str]) -> Result<(), SigningError> {
    if headers
        .iter()
        .any(|header| managed.contains(&header.name.as_str()))
    {
        return Err(SigningError::InvalidHeaders);
    }
    Ok(())
}

fn sort_headers(headers: &mut [SignedHeader]) {
    headers.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
}

fn canonical_host(url: &Url) -> Result<String, SigningError> {
    let host = match url.host().ok_or(SigningError::InvalidUrl)? {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    match url.port() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host),
    }
}

fn canonical_uri(url: &Url) -> Result<String, SigningError> {
    let path = url.path();
    if path.is_empty() {
        return Ok("/".to_owned());
    }
    normalize_percent_encoded(path.as_bytes(), true)
}

fn canonical_query(url: &Url) -> Result<String, SigningError> {
    let Some(query) = url.query() else {
        return Ok(String::new());
    };
    if query.is_empty() {
        return Ok(String::new());
    }

    let mut pairs = Vec::new();
    for component in query.split('&') {
        let (key, value) = component.split_once('=').unwrap_or((component, ""));
        pairs.push((
            normalize_percent_encoded(key.as_bytes(), false)?,
            normalize_percent_encoded(value.as_bytes(), false)?,
        ));
    }
    pairs.sort();
    Ok(pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

fn normalize_percent_encoded(input: &[u8], preserve_slash: bool) -> Result<String, SigningError> {
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if byte == b'/' && preserve_slash {
            output.push('/');
            index += 1;
            continue;
        }
        let decoded = if byte == b'%' {
            let high = input
                .get(index + 1)
                .and_then(|value| from_hex(*value))
                .ok_or(SigningError::InvalidUrl)?;
            let low = input
                .get(index + 2)
                .and_then(|value| from_hex(*value))
                .ok_or(SigningError::InvalidUrl)?;
            index += 3;
            (high << 4) | low
        } else {
            index += 1;
            byte
        };
        encode_rfc3986_byte(decoded, &mut output);
    }
    Ok(output)
}

fn encode_rfc3986_byte(byte: u8, output: &mut String) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
        output.push(char::from(byte));
        return;
    }
    output.push('%');
    output.push(char::from(DIGITS[usize::from(byte >> 4)]));
    output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn format_timestamp(timestamp: OffsetDateTime) -> Result<(String, String), SigningError> {
    if timestamp.offset() != UtcOffset::UTC || !(1..=9999).contains(&timestamp.year()) {
        return Err(SigningError::InvalidTimestamp);
    }
    let month = u8::from(timestamp.month());
    let date = format!("{:04}{month:02}{:02}", timestamp.year(), timestamp.day());
    let timestamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second()
    );
    Ok((date, timestamp))
}
