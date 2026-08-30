//! Bounded cookie-less HTTP transport with validation-before-auth ordering.

use std::fmt::{self, Debug, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use oab_domain::{ClassifiedError, ErrorKind, WindowDuration};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName,
    HeaderValue, LOCATION,
};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::cloud_signing::{
    AwsCredentials, AwsSigV4Signer, SignedHeader, SignedRequest, SigningRequest,
    VolcengineCredentials, VolcengineV4Signer,
};
use crate::endpoint::{EndpointError, EndpointPolicy, ValidatedEndpoint};
use crate::retry::{RetryClock, RetryPolicy, TokioRetryClock, parse_retry_after};

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_AUTHORIZATION_SCHEME_BYTES: usize = 32;
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PUBLIC_REQUEST_HEADERS: usize = 32;
const MAX_PUBLIC_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_ACCEPTED_STATUSES: usize = 16;
const MAX_RESPONSE_HEADERS: usize = 32;
const MAX_RESPONSE_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REDIRECTS: u8 = 10;

/// Typed values permitted in the request `Accept` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAccept {
    /// Browser-compatible wildcard used by provider web APIs.
    Any,
    /// `application/json`.
    Json,
    /// Browser-compatible HTML and XHTML.
    Html,
}

impl RequestAccept {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "*/*",
            Self::Json => "application/json",
            Self::Html => "text/html,application/xhtml+xml",
        }
    }
}

/// Typed values permitted in the request `Content-Type` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestContentType {
    /// `application/json`.
    Json,
    /// OAuth-compatible URL-encoded form data.
    FormUrlEncoded,
    /// Volcengine-compatible URL-encoded form data with an explicit UTF-8 charset.
    FormUrlEncodedUtf8,
    /// AWS JSON protocol version 1.0.
    AwsJson10,
    /// AWS JSON protocol version 1.1.
    AwsJson11,
}

impl RequestContentType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::FormUrlEncoded => "application/x-www-form-urlencoded",
            Self::FormUrlEncodedUtf8 => "application/x-www-form-urlencoded; charset=utf-8",
            Self::AwsJson10 => "application/x-amz-json-1.0",
            Self::AwsJson11 => "application/x-amz-json-1.1",
        }
    }
}

/// Safe transport construction and execution failures.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Request or redirect target failed endpoint policy.
    #[error("provider endpoint policy rejected the request")]
    Endpoint(#[from] EndpointError),
    /// Typed request/configuration value was invalid.
    #[error("provider HTTP request configuration is invalid")]
    InvalidConfiguration,
    /// Cooperative cancellation won the request race.
    #[error("provider request was cancelled")]
    Cancelled,
    /// Per-attempt deadline elapsed.
    #[error("provider request timed out")]
    Timeout,
    /// Connection, TLS, or request transmission failed.
    #[error("provider network request failed")]
    Network,
    /// Successful response exceeded its explicit byte ceiling.
    #[error("provider response exceeded its size limit")]
    ResponseTooLarge,
    /// Response framing, redirects, or body stream was malformed/truncated.
    #[error("provider returned a malformed response")]
    MalformedResponse,
    /// Redirect count exceeded its explicit ceiling.
    #[error("provider response exceeded its redirect limit")]
    TooManyRedirects,
    /// HTTP 401.
    #[error("provider authentication expired")]
    AuthenticationExpired,
    /// HTTP 403.
    #[error("provider denied permission")]
    PermissionDenied,
    /// HTTP 408.
    #[error("provider reported a request timeout")]
    RequestTimeout,
    /// HTTP 429.
    #[error("provider rate limited the request")]
    RateLimited {
        /// Bounded parsed `Retry-After`, if valid.
        retry_after: Option<Duration>,
    },
    /// HTTP 5xx.
    #[error("provider is unavailable")]
    ProviderUnavailable {
        /// Safe numeric response status.
        status: u16,
        /// Bounded parsed `Retry-After`, if valid.
        retry_after: Option<Duration>,
    },
    /// Other non-success HTTP response.
    #[error("provider returned an unexpected status")]
    Api {
        /// Safe numeric response status.
        status: u16,
    },
}

impl TransportError {
    /// Projects raw transport state to the safe domain error vocabulary.
    #[must_use]
    pub fn classified(&self) -> ClassifiedError {
        let kind = match self {
            Self::AuthenticationExpired => ErrorKind::AuthenticationExpired,
            Self::PermissionDenied => ErrorKind::PermissionDenied,
            Self::RateLimited { .. } => ErrorKind::RateLimited,
            Self::ProviderUnavailable { .. } => ErrorKind::ProviderUnavailable,
            Self::Cancelled | Self::Timeout | Self::Network | Self::RequestTimeout => {
                ErrorKind::Network
            }
            Self::ResponseTooLarge | Self::MalformedResponse | Self::TooManyRedirects => {
                ErrorKind::Parse
            }
            Self::Endpoint(_) | Self::InvalidConfiguration | Self::Api { .. } => ErrorKind::Api,
        };
        self.classified_as(kind)
    }

    pub(crate) fn classified_as(&self, kind: ErrorKind) -> ClassifiedError {
        let error = ClassifiedError::new(kind);
        let Some(delay) = self.retry_after() else {
            return error;
        };
        let seconds = delay.as_secs().max(1);
        let Ok(duration) = WindowDuration::from_seconds(seconds) else {
            return error;
        };
        error.clone().with_retry_after(duration).unwrap_or(error)
    }

    /// Returns the provider's numeric HTTP status when this failure came from
    /// a completed HTTP response rather than connection or parsing state.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::AuthenticationExpired => Some(401),
            Self::PermissionDenied => Some(403),
            Self::RequestTimeout => Some(408),
            Self::RateLimited { .. } => Some(429),
            Self::ProviderUnavailable { status, .. } | Self::Api { status } => Some(*status),
            Self::Endpoint(_)
            | Self::InvalidConfiguration
            | Self::Cancelled
            | Self::Timeout
            | Self::Network
            | Self::ResponseTooLarge
            | Self::MalformedResponse
            | Self::TooManyRedirects => None,
        }
    }

    /// Whether the shared one-retry policy may retry this failure.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout
                | Self::Network
                | Self::RequestTimeout
                | Self::RateLimited { .. }
                | Self::ProviderUnavailable { .. }
        )
    }

    /// Bounded server-requested delay, if any.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } | Self::ProviderUnavailable { retry_after, .. } => {
                *retry_after
            }
            _ => None,
        }
    }
}

/// Explicit timeout, size, redirect, and retry ceilings.
#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    connect_timeout: Duration,
    request_timeout: Duration,
    max_response_bytes: usize,
    max_redirects: u8,
    retry: RetryPolicy,
}

impl TransportConfig {
    /// Creates a bounded transport configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfiguration`] for zero deadlines,
    /// zero/excessive response caps, excessive redirect counts, or invalid
    /// retry delays.
    pub fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        max_response_bytes: usize,
        max_redirects: u8,
        retry: RetryPolicy,
    ) -> Result<Self, TransportError> {
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_redirects > MAX_REDIRECTS
            || !retry.is_valid()
        {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            connect_timeout,
            request_timeout,
            max_response_bytes,
            max_redirects,
            retry,
        })
    }
}

/// Zeroizing bounded secret used only by typed authentication headers.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    fn new(value: impl Into<String>) -> Result<Self, TransportError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains(['\r', '\n']) {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Debug for SecretValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(<redacted>)")
    }
}

/// Authentication forms the host may attach only to a validated endpoint.
pub enum Authentication {
    /// `Authorization: Bearer ...`.
    Bearer(SecretValue),
    /// `Authorization: <scheme> ...` for a validated non-Bearer vendor scheme.
    AuthorizationScheme {
        /// Public RFC token placed before the secret.
        scheme: String,
        /// Secret authorization credential.
        value: SecretValue,
    },
    /// Provider-specific secret header.
    ApiKey {
        /// Validated header name.
        name: HeaderName,
        /// Redacted, zeroizing value.
        value: SecretValue,
    },
    /// Explicit manual Cookie header; never a shared cookie jar.
    Cookie(SecretValue),
    /// AWS Signature Version 4, regenerated after endpoint validation for each attempt.
    AwsSigV4 {
        /// Fixed region/service signer configuration.
        signer: AwsSigV4Signer,
        /// Redacted, zeroizing AWS credentials.
        credentials: AwsCredentials,
    },
    /// Volcengine V4 signing, regenerated after endpoint validation for each attempt.
    VolcengineV4 {
        /// Redacted, zeroizing Volcengine credentials and region.
        credentials: VolcengineCredentials,
    },
}

impl Authentication {
    /// Creates bearer authentication.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or line-breaking values.
    pub fn bearer(value: impl Into<String>) -> Result<Self, TransportError> {
        SecretValue::new(value).map(Self::Bearer)
    }

    /// Creates a vendor authorization scheme such as `Token`.
    ///
    /// # Errors
    ///
    /// Rejects invalid/oversized RFC token schemes and unsafe secret values.
    pub fn authorization_scheme(
        scheme: impl AsRef<str>,
        value: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let scheme = scheme.as_ref();
        if scheme.is_empty()
            || scheme.len() > MAX_AUTHORIZATION_SCHEME_BYTES
            || !scheme.bytes().all(is_http_token_byte)
        {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self::AuthorizationScheme {
            scheme: scheme.to_owned(),
            value: SecretValue::new(value)?,
        })
    }

    /// Creates a provider-specific API-key header.
    ///
    /// # Errors
    ///
    /// Rejects invalid/reserved header names and unsafe secret values.
    pub fn api_key(
        name: impl AsRef<str>,
        value: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let name = HeaderName::from_bytes(name.as_ref().as_bytes())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        if is_reserved_api_key_header(&name) {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self::ApiKey {
            name,
            value: SecretValue::new(value)?,
        })
    }

    /// Creates an explicit manual Cookie header.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or line-breaking values.
    pub fn cookie(value: impl Into<String>) -> Result<Self, TransportError> {
        SecretValue::new(value).map(Self::Cookie)
    }

    /// Creates AWS Signature Version 4 authentication for one region/service scope.
    ///
    /// The signature timestamp comes from the transport's injected retry clock and
    /// is sampled again for every retry and validated redirect.
    ///
    /// # Errors
    ///
    /// Rejects malformed or oversized region/service scope components.
    pub fn aws_sig_v4(
        credentials: AwsCredentials,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let signer = AwsSigV4Signer::new(region, service)
            .map_err(|_| TransportError::InvalidConfiguration)?;
        Ok(Self::AwsSigV4 {
            signer,
            credentials,
        })
    }

    /// Creates Volcengine V4 authentication for credentials containing the scope region.
    #[must_use]
    pub const fn volcengine_v4(credentials: VolcengineCredentials) -> Self {
        Self::VolcengineV4 { credentials }
    }

    const fn uses_cloud_signing(&self) -> bool {
        matches!(self, Self::AwsSigV4 { .. } | Self::VolcengineV4 { .. })
    }

    fn apply(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, TransportError> {
        match self {
            Self::Bearer(secret) => {
                let value = Zeroizing::new(format!("Bearer {}", secret.expose()));
                Ok(builder.header(AUTHORIZATION, sensitive_header(&value)?))
            }
            Self::AuthorizationScheme { scheme, value } => {
                let value = Zeroizing::new(format!("{scheme} {}", value.expose()));
                Ok(builder.header(AUTHORIZATION, sensitive_header(&value)?))
            }
            Self::ApiKey { name, value } => {
                Ok(builder.header(name, sensitive_header(value.expose())?))
            }
            Self::Cookie(secret) => Ok(builder.header(COOKIE, sensitive_header(secret.expose())?)),
            Self::AwsSigV4 { .. } | Self::VolcengineV4 { .. } => {
                Err(TransportError::InvalidConfiguration)
            }
        }
    }

    fn sign_cloud_request(
        &self,
        request: &HttpRequest,
        endpoint: &ValidatedEndpoint,
        timestamp: OffsetDateTime,
    ) -> Result<Option<SignedRequest>, TransportError> {
        match self {
            Self::AwsSigV4 {
                signer,
                credentials,
            } => signer
                .sign(signing_request(request, endpoint)?, credentials, timestamp)
                .map(Some)
                .map_err(|_| TransportError::InvalidConfiguration),
            Self::VolcengineV4 { credentials } => VolcengineV4Signer::sign(
                signing_request(request, endpoint)?,
                credentials,
                timestamp,
            )
            .map(Some)
            .map_err(|_| TransportError::InvalidConfiguration),
            Self::Bearer(_)
            | Self::AuthorizationScheme { .. }
            | Self::ApiKey { .. }
            | Self::Cookie(_) => Ok(None),
        }
    }
}

impl Debug for Authentication {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => formatter.write_str("Authentication::Bearer(<redacted>)"),
            Self::AuthorizationScheme { scheme, .. } => formatter
                .debug_struct("Authentication::AuthorizationScheme")
                .field("scheme", scheme)
                .field("value", &"<redacted>")
                .finish(),
            Self::ApiKey { name, .. } => formatter
                .debug_struct("Authentication::ApiKey")
                .field("name", name)
                .field("value", &"<redacted>")
                .finish(),
            Self::Cookie(_) => formatter.write_str("Authentication::Cookie(<redacted>)"),
            Self::AwsSigV4 { signer, .. } => formatter
                .debug_struct("Authentication::AwsSigV4")
                .field("signer", signer)
                .field("credentials", &"<redacted>")
                .finish(),
            Self::VolcengineV4 { .. } => formatter
                .debug_struct("Authentication::VolcengineV4")
                .field("credentials", &"<redacted>")
                .finish(),
        }
    }
}

/// Reusable request description. Its debug view omits path, query, body, and auth.
pub struct HttpRequest {
    method: Method,
    url: Url,
    authentication: Option<Authentication>,
    public_headers: Vec<(HeaderName, HeaderValue)>,
    sensitive_headers: Vec<(HeaderName, SecretValue)>,
    accepted_statuses: Vec<StatusCode>,
    response_headers: Vec<HeaderName>,
    body: Vec<u8>,
    accept: Option<RequestAccept>,
    content_type: Option<RequestContentType>,
}

impl HttpRequest {
    /// Creates a body-free GET request.
    #[must_use]
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::GET,
            url,
            authentication: None,
            public_headers: Vec::new(),
            sensitive_headers: Vec::new(),
            accepted_statuses: Vec::new(),
            response_headers: Vec::new(),
            body: Vec::new(),
            accept: None,
            content_type: None,
        }
    }

    /// Creates a body-free GET request that advertises JSON response support.
    #[must_use]
    pub fn get_json(url: Url) -> Self {
        let mut request = Self::get(url);
        request.accept = Some(RequestAccept::Json);
        request
    }

    /// Creates a bounded POST request body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the request ceiling.
    pub fn post(url: Url, body: Vec<u8>) -> Result<Self, TransportError> {
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            method: Method::POST,
            url,
            authentication: None,
            public_headers: Vec::new(),
            sensitive_headers: Vec::new(),
            accepted_statuses: Vec::new(),
            response_headers: Vec::new(),
            body,
            accept: None,
            content_type: None,
        })
    }

    /// Creates a bounded JSON POST request body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the request ceiling.
    pub fn post_json(url: Url, body: Vec<u8>) -> Result<Self, TransportError> {
        let has_body = !body.is_empty();
        let mut request = Self::post(url, body)?;
        request.accept = Some(RequestAccept::Json);
        if has_body {
            request.content_type = Some(RequestContentType::Json);
        }
        Ok(request)
    }

    /// Attaches typed authentication to be applied after endpoint validation.
    #[must_use]
    pub fn authentication(mut self, authentication: Authentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Sets a transport-owned, typed `Accept` value.
    #[must_use]
    pub fn accept(mut self, accept: RequestAccept) -> Self {
        self.accept = Some(accept);
        self
    }

    /// Sets a transport-owned, typed `Content-Type` value.
    #[must_use]
    pub fn content_type(mut self, content_type: RequestContentType) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Requests an explicit JSON content type for a body-free request.
    ///
    /// Some provider APIs require the same media-type headers on GET and POST.
    #[must_use]
    pub fn empty_json_content_type(mut self) -> Self {
        self.content_type = Some(RequestContentType::Json);
        self
    }

    /// Allows a bounded set of error statuses to return as normal responses.
    ///
    /// Success statuses are always accepted. Redirect and informational
    /// statuses remain transport-owned and cannot be accepted here.
    ///
    /// # Errors
    ///
    /// Returns an error for more than 16 entries, duplicate entries, invalid
    /// status numbers, or any non-error status.
    pub fn accepted_statuses(mut self, statuses: &[u16]) -> Result<Self, TransportError> {
        if statuses.len() > MAX_ACCEPTED_STATUSES {
            return Err(TransportError::InvalidConfiguration);
        }
        let mut accepted = Vec::with_capacity(statuses.len());
        for status in statuses {
            let status =
                StatusCode::from_u16(*status).map_err(|_| TransportError::InvalidConfiguration)?;
            if (!status.is_client_error() && !status.is_server_error())
                || accepted.contains(&status)
            {
                return Err(TransportError::InvalidConfiguration);
            }
            accepted.push(status);
        }
        self.accepted_statuses = accepted;
        Ok(self)
    }

    /// Selects the only response headers retained by the transport.
    ///
    /// Names are matched case-insensitively. Sensitive authentication,
    /// cookie, redirect, and hop-by-hop headers cannot be retained.
    ///
    /// # Errors
    ///
    /// Returns an error for more than 32 entries, duplicate/invalid names, or
    /// a reserved response header.
    pub fn response_headers(mut self, names: &[&str]) -> Result<Self, TransportError> {
        if names.len() > MAX_RESPONSE_HEADERS {
            return Err(TransportError::InvalidConfiguration);
        }
        let mut selected = Vec::with_capacity(names.len());
        for name in names {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| TransportError::InvalidConfiguration)?;
            if is_reserved_response_header(&name) || selected.contains(&name) {
                return Err(TransportError::InvalidConfiguration);
            }
            selected.push(name);
        }
        self.response_headers = selected;
        Ok(self)
    }

    /// Attaches one bounded, explicitly non-secret provider metadata header.
    ///
    /// Authentication, cookies, framing headers, and JSON media-type headers
    /// remain owned by the transport and cannot be replaced here.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or reserved names, invalid values, an
    /// oversized value, or too many metadata headers.
    pub fn public_header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, TransportError> {
        if self.public_headers.len() + self.sensitive_headers.len() >= MAX_PUBLIC_REQUEST_HEADERS
            || value.as_ref().len() > MAX_PUBLIC_HEADER_VALUE_BYTES
        {
            return Err(TransportError::InvalidConfiguration);
        }
        let name = HeaderName::from_bytes(name.as_ref().as_bytes())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        if is_reserved_public_header(&name) || self.has_metadata_header(&name) {
            return Err(TransportError::InvalidConfiguration);
        }
        let value = HeaderValue::from_str(value.as_ref())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        self.public_headers.push((name, value));
        Ok(self)
    }

    /// Attaches one bounded, explicitly non-auth provider metadata header whose
    /// value is zeroized with the request.
    ///
    /// This is intended for narrowly allowlisted browser-fingerprint metadata
    /// copied from a manual capture. Cookie and authorization credentials still
    /// belong in [`Authentication`]. Host, framing, redirect, media-type, and
    /// duplicate headers are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or reserved names, unsafe/oversized values,
    /// duplicate names, or too many metadata headers.
    pub fn sensitive_header(
        mut self,
        name: impl AsRef<str>,
        value: impl Into<String>,
    ) -> Result<Self, TransportError> {
        if self.public_headers.len() + self.sensitive_headers.len() >= MAX_PUBLIC_REQUEST_HEADERS {
            return Err(TransportError::InvalidConfiguration);
        }
        let name = HeaderName::from_bytes(name.as_ref().as_bytes())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        if is_reserved_public_header(&name) || self.has_metadata_header(&name) {
            return Err(TransportError::InvalidConfiguration);
        }
        let value = SecretValue::new(value)?;
        if value.expose().len() > MAX_PUBLIC_HEADER_VALUE_BYTES {
            return Err(TransportError::InvalidConfiguration);
        }
        self.sensitive_headers.push((name, value));
        Ok(self)
    }

    fn has_metadata_header(&self, name: &HeaderName) -> bool {
        self.public_headers
            .iter()
            .any(|(candidate, _)| candidate == name)
            || self
                .sensitive_headers
                .iter()
                .any(|(candidate, _)| candidate == name)
    }
}

impl Debug for HttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("scheme", &self.url.scheme())
            .field("host", &self.url.host_str())
            .field("path", &"<redacted>")
            .field("query", &"<redacted>")
            .field("authentication", &self.authentication)
            .field("public_header_count", &self.public_headers.len())
            .field("sensitive_header_count", &self.sensitive_headers.len())
            .field("accepted_status_count", &self.accepted_statuses.len())
            .field("response_header_count", &self.response_headers.len())
            .field("accept", &self.accept)
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Bounded successful response. Debug output never includes headers or body.
pub struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    headers: Vec<(HeaderName, String)>,
    endpoint: ValidatedEndpoint,
}

impl HttpResponse {
    /// Numeric success status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Bounded response bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns one explicitly selected response header.
    ///
    /// Lookup is ASCII case-insensitive. Unselected headers are never retained
    /// and therefore always return `None`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    /// Parses JSON without including raw body text in errors.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error for malformed or incompatible JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, ClassifiedError> {
        serde_json::from_slice(&self.body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
    }
}

impl Debug for HttpResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("header_count", &self.headers.len())
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Per-provider/account client. Cookie persistence is not compiled or enabled.
pub struct HttpTransport<C = TokioRetryClock> {
    client: Client,
    endpoints: EndpointPolicy,
    config: TransportConfig,
    clock: C,
}

impl HttpTransport<TokioRetryClock> {
    /// Creates a production transport using Tokio/system time.
    ///
    /// # Errors
    ///
    /// Returns a safe configuration error if the TLS/client builder fails.
    pub fn new(endpoints: EndpointPolicy, config: TransportConfig) -> Result<Self, TransportError> {
        Self::with_clock(endpoints, config, TokioRetryClock)
    }
}

impl<C: RetryClock> HttpTransport<C> {
    /// Creates a transport with an injected deterministic retry clock.
    ///
    /// # Errors
    ///
    /// Returns a safe configuration error if the TLS/client builder fails.
    pub fn with_clock(
        endpoints: EndpointPolicy,
        config: TransportConfig,
        clock: C,
    ) -> Result<Self, TransportError> {
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("omarchy-ai-bar/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| TransportError::InvalidConfiguration)?;
        Ok(Self {
            client,
            endpoints,
            config,
            clock,
        })
    }

    /// Sends with validation, bounded redirects/body, deadline, cancellation,
    /// and at most the configured one retry.
    ///
    /// # Errors
    ///
    /// Returns only stable redacted [`TransportError`] variants.
    pub async fn send(
        &self,
        request: &HttpRequest,
        cancellation: &CancellationToken,
    ) -> Result<HttpResponse, TransportError> {
        let mut completed_retries = 0_u8;
        loop {
            let result = self.send_attempt(request, cancellation).await;
            let Err(error) = result else {
                return result;
            };
            let Some(delay) = self.config.retry.delay(completed_retries, &error) else {
                return Err(error);
            };
            completed_retries = completed_retries.saturating_add(1);
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(TransportError::Cancelled),
                () = self.clock.sleep(delay) => {}
            }
        }
    }

    async fn send_attempt(
        &self,
        request: &HttpRequest,
        cancellation: &CancellationToken,
    ) -> Result<HttpResponse, TransportError> {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(TransportError::Cancelled),
            result = tokio::time::timeout(
                self.config.request_timeout,
                self.follow_redirects(request),
            ) => result.unwrap_or(Err(TransportError::Timeout)),
        }
    }

    async fn follow_redirects(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, TransportError> {
        let mut current = request.url.clone();
        let mut redirect_count = 0_u8;
        loop {
            let endpoint = self.endpoints.validate(&current)?;
            let signed = match request.authentication.as_ref() {
                Some(authentication) if authentication.uses_cloud_signing() => authentication
                    .sign_cloud_request(
                        request,
                        &endpoint,
                        system_time_utc(self.clock.wall_now())?,
                    )?,
                Some(_) | None => None,
            };
            let builder = if let Some(signed) = &signed {
                let mut builder = self
                    .client
                    .request(signed.method().clone(), signed.url().clone());
                for header in signed.headers() {
                    builder = builder.header(header.name(), transport_signed_header_value(header));
                }
                if !signed.body().is_empty() {
                    builder = builder.body(signed.body().to_vec());
                }
                builder
            } else {
                let mut builder = self
                    .client
                    .request(request.method.clone(), endpoint.url().clone());
                if let Some(accept) = request.accept {
                    builder = builder.header(ACCEPT, accept.as_str());
                }
                if let Some(content_type) = request.content_type {
                    builder = builder.header(CONTENT_TYPE, content_type.as_str());
                }
                if !request.body.is_empty() {
                    builder = builder.body(request.body.clone());
                }
                for (name, value) in &request.public_headers {
                    builder = builder.header(name, value);
                }
                for (name, value) in &request.sensitive_headers {
                    builder = builder.header(name, sensitive_header(value.expose())?);
                }
                if let Some(authentication) = &request.authentication {
                    builder = authentication.apply(builder)?;
                }
                builder
            };
            let response = builder.send().await.map_err(|_| TransportError::Network)?;
            if response.status().is_redirection() {
                if request.method != Method::GET && request.method != Method::HEAD {
                    return Err(TransportError::MalformedResponse);
                }
                if redirect_count == self.config.max_redirects {
                    return Err(TransportError::TooManyRedirects);
                }
                redirect_count = redirect_count.saturating_add(1);
                current = redirect_target(&current, response.headers())?;
                self.endpoints.validate(&current)?;
                continue;
            }

            let status = response.status();
            if !status.is_success() && !request.accepted_statuses.contains(&status) {
                return Err(self.status_error(status, response.headers()));
            }
            let selected_headers = select_response_headers(response.headers(), request)?;
            if response
                .content_length()
                .is_some_and(|length| length > self.config.max_response_bytes as u64)
            {
                return Err(TransportError::ResponseTooLarge);
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| TransportError::MalformedResponse)?;
                let next_length = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(TransportError::ResponseTooLarge)?;
                if next_length > self.config.max_response_bytes {
                    return Err(TransportError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(HttpResponse {
                status: status.as_u16(),
                body,
                headers: selected_headers,
                endpoint,
            });
        }
    }

    fn status_error(&self, status: StatusCode, headers: &HeaderMap) -> TransportError {
        let retry_after = headers.get(reqwest::header::RETRY_AFTER).and_then(|value| {
            parse_retry_after(value, self.clock.wall_now(), self.config.retry.max_delay())
        });
        match status {
            StatusCode::UNAUTHORIZED => TransportError::AuthenticationExpired,
            StatusCode::FORBIDDEN => TransportError::PermissionDenied,
            StatusCode::REQUEST_TIMEOUT => TransportError::RequestTimeout,
            StatusCode::TOO_MANY_REQUESTS => TransportError::RateLimited { retry_after },
            status if status.is_server_error() => TransportError::ProviderUnavailable {
                status: status.as_u16(),
                retry_after,
            },
            status => TransportError::Api {
                status: status.as_u16(),
            },
        }
    }
}

fn redirect_target(current: &Url, headers: &HeaderMap) -> Result<Url, TransportError> {
    let location = headers
        .get(LOCATION)
        .ok_or(TransportError::MalformedResponse)?
        .to_str()
        .map_err(|_| TransportError::MalformedResponse)?;
    current
        .join(location)
        .map_err(|_| TransportError::MalformedResponse)
}

fn sensitive_header(value: &str) -> Result<HeaderValue, TransportError> {
    let mut value =
        HeaderValue::from_str(value).map_err(|_| TransportError::InvalidConfiguration)?;
    value.set_sensitive(true);
    Ok(value)
}

fn signing_request(
    request: &HttpRequest,
    endpoint: &ValidatedEndpoint,
) -> Result<SigningRequest, TransportError> {
    let mut signing = SigningRequest::for_validated_endpoint(
        request.method.clone(),
        endpoint,
        request.body.clone(),
    )
    .map_err(|_| TransportError::InvalidConfiguration)?;
    if let Some(accept) = request.accept {
        signing = signing
            .with_header(ACCEPT.as_str(), accept.as_str())
            .map_err(|_| TransportError::InvalidConfiguration)?;
    }
    if let Some(content_type) = request.content_type {
        signing = signing
            .with_header(CONTENT_TYPE.as_str(), content_type.as_str())
            .map_err(|_| TransportError::InvalidConfiguration)?;
    }
    for (name, value) in &request.public_headers {
        signing = signing
            .with_header(
                name.as_str(),
                value
                    .to_str()
                    .map_err(|_| TransportError::InvalidConfiguration)?,
            )
            .map_err(|_| TransportError::InvalidConfiguration)?;
    }
    for (name, value) in &request.sensitive_headers {
        signing = signing
            .with_header(name.as_str(), value.expose())
            .map_err(|_| TransportError::InvalidConfiguration)?;
    }
    Ok(signing)
}

fn transport_signed_header_value(header: &SignedHeader) -> HeaderValue {
    let mut value = header.to_header_value();
    if header.name() == AUTHORIZATION || header.name().as_str() == "x-amz-security-token" {
        value.set_sensitive(true);
    }
    value
}

fn system_time_utc(value: SystemTime) -> Result<OffsetDateTime, TransportError> {
    let nanos = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::from(duration.as_secs())
            .checked_mul(1_000_000_000)
            .and_then(|nanos| nanos.checked_add(i128::from(duration.subsec_nanos()))),
        Err(error) => i128::from(error.duration().as_secs())
            .checked_mul(1_000_000_000)
            .and_then(|nanos| nanos.checked_add(i128::from(error.duration().subsec_nanos())))
            .and_then(i128::checked_neg),
    }
    .ok_or(TransportError::InvalidConfiguration)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| TransportError::InvalidConfiguration)
}

const fn is_http_token_byte(byte: u8) -> bool {
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
}

fn is_reserved_api_key_header(name: &HeaderName) -> bool {
    matches!(name, &AUTHORIZATION | &COOKIE | &CONTENT_LENGTH | &LOCATION)
        || matches!(
            name.as_str(),
            "connection"
                | "host"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "set-cookie"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "www-authenticate"
        )
}

fn is_reserved_public_header(name: &HeaderName) -> bool {
    is_reserved_api_key_header(name) || matches!(name, &ACCEPT | &CONTENT_TYPE)
}

fn is_reserved_response_header(name: &HeaderName) -> bool {
    matches!(name, &AUTHORIZATION | &COOKIE | &CONTENT_LENGTH | &LOCATION)
        || matches!(
            name.as_str(),
            "connection"
                | "host"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "set-cookie"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "www-authenticate"
        )
}

fn select_response_headers(
    headers: &HeaderMap,
    request: &HttpRequest,
) -> Result<Vec<(HeaderName, String)>, TransportError> {
    let mut selected = Vec::with_capacity(request.response_headers.len());
    for name in &request.response_headers {
        let Some(value) = headers.get(name) else {
            continue;
        };
        if value.as_bytes().len() > MAX_RESPONSE_HEADER_VALUE_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        let value = value
            .to_str()
            .map_err(|_| TransportError::MalformedResponse)?;
        selected.push((name.clone(), value.to_owned()));
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::EndpointClass;

    fn signing_endpoint(url: &Url) -> ValidatedEndpoint {
        EndpointPolicy::new([("https://example.com:8443", EndpointClass::PublicHttps)])
            .expect("signing endpoint policy")
            .validate(url)
            .expect("validated signing endpoint")
    }

    fn fixed_timestamp() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_440_938_160).expect("fixture timestamp")
    }

    fn signed_header<'a>(signed: &'a SignedRequest, name: &str) -> &'a SignedHeader {
        signed
            .headers()
            .iter()
            .find(|header| header.name().as_str() == name)
            .expect("signed header")
    }

    #[test]
    fn aws_auth_signs_the_final_typed_request_and_redacts_credentials() {
        const ACCESS_KEY: &str = "aws-access-key-canary";
        const SECRET_KEY: &str = "aws-secret-key-canary";
        const SESSION_TOKEN: &str = "aws-session-token-canary";
        let credentials = AwsCredentials::new(ACCESS_KEY, SECRET_KEY, Some(SESSION_TOKEN))
            .expect("AWS credentials");
        let authentication = Authentication::aws_sig_v4(credentials, "us-east-1", "bedrock")
            .expect("AWS authentication");
        let url = Url::parse("https://example.com:8443/models/a%20b?z=2&a=1").expect("fixture URL");
        let request = HttpRequest::post(url.clone(), b"exact-body".to_vec())
            .expect("request")
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::AwsJson11)
            .public_header("x-amz-target", "Bedrock.List")
            .expect("public target header");
        let signed = authentication
            .sign_cloud_request(&request, &signing_endpoint(&url), fixed_timestamp())
            .expect("signed request")
            .expect("cloud authentication");

        assert_eq!(signed.method(), &Method::POST);
        assert_eq!(signed.url(), &url);
        assert_eq!(signed.body(), b"exact-body");
        assert_eq!(signed.header("accept"), Some("application/json"));
        assert_eq!(
            signed.header("content-type"),
            Some("application/x-amz-json-1.1")
        );
        assert_eq!(signed.header("x-amz-target"), Some("Bedrock.List"));
        assert_eq!(signed.header("host"), Some("example.com:8443"));
        assert!(
            signed
                .header("authorization")
                .is_some_and(|value| value.contains("SignedHeaders=accept;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target"))
        );
        assert!(
            transport_signed_header_value(signed_header(&signed, "authorization")).is_sensitive()
        );
        assert!(
            transport_signed_header_value(signed_header(&signed, "x-amz-security-token"))
                .is_sensitive()
        );
        assert!(
            transport_signed_header_value(signed_header(&signed, "content-type")).is_sensitive()
        );

        let debug = format!("{authentication:?} {request:?} {signed:?}");
        for canary in [ACCESS_KEY, SECRET_KEY, SESSION_TOKEN, "exact-body", "a%20b"] {
            assert!(!debug.contains(canary), "debug leaked {canary}: {debug}");
        }
    }

    #[test]
    fn volcengine_auth_preserves_the_exact_utf8_form_media_type() {
        let credentials = VolcengineCredentials::new(
            "volc-access-key-canary",
            "volc-secret-key-canary",
            "cn-beijing",
        )
        .expect("Volcengine credentials");
        let authentication = Authentication::volcengine_v4(credentials);
        let url = Url::parse("https://example.com:8443/api/v3/billing/usage").expect("fixture URL");
        let request = HttpRequest::post(url.clone(), b"Action=Usage".to_vec())
            .expect("request")
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncodedUtf8)
            .public_header("x-provider-action", "Usage")
            .expect("public action header");
        let signed = authentication
            .sign_cloud_request(&request, &signing_endpoint(&url), fixed_timestamp())
            .expect("signed request")
            .expect("cloud authentication");

        assert_eq!(signed.method(), &Method::POST);
        assert_eq!(signed.url(), &url);
        assert_eq!(signed.body(), b"Action=Usage");
        assert_eq!(
            signed.header("content-type"),
            Some("application/x-www-form-urlencoded; charset=utf-8")
        );
        assert_eq!(signed.header("accept"), Some("application/json"));
        assert_eq!(signed.header("x-provider-action"), Some("Usage"));
        assert!(
            transport_signed_header_value(signed_header(&signed, "authorization")).is_sensitive()
        );

        let debug = format!("{authentication:?} {request:?} {signed:?}");
        for canary in [
            "volc-access-key-canary",
            "volc-secret-key-canary",
            "Action=Usage",
        ] {
            assert!(!debug.contains(canary), "debug leaked {canary}: {debug}");
        }
    }

    #[test]
    fn system_time_conversion_preserves_both_sides_of_the_epoch() {
        assert_eq!(
            system_time_utc(UNIX_EPOCH).expect("epoch").unix_timestamp(),
            0
        );
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_nanos(1))
            .expect("pre-epoch time");
        assert_eq!(
            system_time_utc(before_epoch)
                .expect("pre-epoch")
                .unix_timestamp_nanos(),
            -1
        );
    }
}
