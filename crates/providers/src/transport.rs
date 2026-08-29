//! Bounded cookie-less HTTP transport with validation-before-auth ordering.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use futures_util::StreamExt;
use oab_domain::{ClassifiedError, ErrorKind, WindowDuration};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName,
    HeaderValue, LOCATION,
};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::endpoint::{EndpointError, EndpointPolicy, ValidatedEndpoint};
use crate::retry::{RetryClock, RetryPolicy, TokioRetryClock, parse_retry_after};

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_AUTHORIZATION_SCHEME_BYTES: usize = 32;
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PUBLIC_REQUEST_HEADERS: usize = 32;
const MAX_PUBLIC_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REDIRECTS: u8 = 10;

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
        }
    }
}

/// Reusable request description. Its debug view omits path, query, body, and auth.
pub struct HttpRequest {
    method: Method,
    url: Url,
    authentication: Option<Authentication>,
    public_headers: Vec<(HeaderName, HeaderValue)>,
    body: Vec<u8>,
    json: bool,
    empty_json_content_type: bool,
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
            body: Vec::new(),
            json: false,
            empty_json_content_type: false,
        }
    }

    /// Creates a body-free GET request that advertises JSON response support.
    #[must_use]
    pub fn get_json(url: Url) -> Self {
        let mut request = Self::get(url);
        request.json = true;
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
            body,
            json: false,
            empty_json_content_type: false,
        })
    }

    /// Creates a bounded JSON POST request body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the request ceiling.
    pub fn post_json(url: Url, body: Vec<u8>) -> Result<Self, TransportError> {
        let mut request = Self::post(url, body)?;
        request.json = true;
        Ok(request)
    }

    /// Attaches typed authentication to be applied after endpoint validation.
    #[must_use]
    pub fn authentication(mut self, authentication: Authentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Requests an explicit JSON content type for a body-free request.
    ///
    /// Some provider APIs require the same media-type headers on GET and POST.
    #[must_use]
    pub fn empty_json_content_type(mut self) -> Self {
        self.empty_json_content_type = true;
        self
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
        if self.public_headers.len() >= MAX_PUBLIC_REQUEST_HEADERS
            || value.as_ref().len() > MAX_PUBLIC_HEADER_VALUE_BYTES
        {
            return Err(TransportError::InvalidConfiguration);
        }
        let name = HeaderName::from_bytes(name.as_ref().as_bytes())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        if is_reserved_public_header(&name) {
            return Err(TransportError::InvalidConfiguration);
        }
        let value = HeaderValue::from_str(value.as_ref())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        self.public_headers.push((name, value));
        Ok(self)
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
            .field("json", &self.json)
            .field("empty_json_content_type", &self.empty_json_content_type)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Bounded successful response. Debug output never includes headers or body.
pub struct HttpResponse {
    status: u16,
    body: Vec<u8>,
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
            let mut builder = self
                .client
                .request(request.method.clone(), endpoint.url().clone());
            if request.json {
                builder = builder.header(ACCEPT, "application/json");
                if !request.body.is_empty() || request.empty_json_content_type {
                    builder = builder.header(CONTENT_TYPE, "application/json");
                }
            }
            if !request.body.is_empty() {
                builder = builder.body(request.body.clone());
            }
            for (name, value) in &request.public_headers {
                builder = builder.header(name, value);
            }
            if let Some(authentication) = &request.authentication {
                builder = authentication.apply(builder)?;
            }
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
            if !status.is_success() {
                return Err(self.status_error(status, response.headers()));
            }
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
