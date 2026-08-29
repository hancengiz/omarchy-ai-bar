//! Account-scoped fixed-endpoint API-key clients.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

use oab_domain::{AccountScope, ClassifiedError, ErrorKind};
use reqwest::header::HeaderName;
use url::Url;
use zeroize::Zeroizing;

use crate::context::ProviderContext;
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::transport::{Authentication, HttpRequest, HttpResponse, HttpTransport, TransportConfig};

const MAX_API_KEY_BYTES: usize = 16 * 1024;

/// A bounded, trimmed, zeroizing API key.
#[derive(Clone)]
pub struct ApiKeyCredential {
    value: Zeroizing<String>,
}

impl ApiKeyCredential {
    /// Resolves the first non-empty value using the supplied precedence order.
    ///
    /// Matching single or double quotes around environment-style values are
    /// removed to preserve the baseline configuration behavior.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error if no usable key is present.
    pub fn resolve(
        environment: &BTreeMap<String, String>,
        keys: &[&str],
    ) -> Result<Self, ClassifiedError> {
        keys.iter()
            .filter_map(|key| environment.get(*key))
            .find_map(|value| clean_secret(value))
            .and_then(|value| Self::from_cleaned(value).ok())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
    }

    /// Validates one already-selected key.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for empty or oversized input.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ClassifiedError> {
        let Some(value) = clean_secret(value.as_ref()) else {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        };
        Self::from_cleaned(value)
    }

    fn from_cleaned(value: Zeroizing<String>) -> Result<Self, ClassifiedError> {
        if value.len() > MAX_API_KEY_BYTES || value.contains(['\r', '\n']) {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        Ok(Self { value })
    }

    /// Reports whether the credential has a decodable JWT object payload.
    ///
    /// Only the boolean classification leaves this secret-owning boundary.
    #[must_use]
    pub fn is_structured_jwt(&self) -> bool {
        jwt_payload_is_object(self.value.as_bytes())
    }

    fn authentication(&self, header: &HeaderName) -> Result<Authentication, ClassifiedError> {
        Authentication::api_key(header.as_str(), self.value.as_str().to_owned())
            .map_err(|error| error.classified())
    }

    fn bearer_authentication(&self) -> Result<Authentication, ClassifiedError> {
        Authentication::bearer(self.value.as_str().to_owned()).map_err(|error| error.classified())
    }

    fn authorization_scheme(&self, scheme: &str) -> Result<Authentication, ClassifiedError> {
        Authentication::authorization_scheme(scheme, self.value.as_str().to_owned())
            .map_err(|error| error.classified())
    }
}

impl Debug for ApiKeyCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyCredential(<redacted>)")
    }
}

/// One exact provider/account client with no shared cookie state.
pub struct FixedApiClient {
    scope: AccountScope,
    base_url: Url,
    authentication: ApiKeyAuthentication,
    credential: ApiKeyCredential,
    config: TransportConfig,
    transport: HttpTransport,
}

#[derive(Clone)]
enum ApiKeyAuthentication {
    Bearer,
    AuthorizationScheme(String),
    Header(HeaderName),
}

impl FixedApiClient {
    /// Creates an exact-origin API-key client.
    ///
    /// The typed endpoint class must be selected explicitly; request
    /// credentials are attached only after the shared transport validates the
    /// complete request or redirect URL.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for malformed endpoints, header names, or
    /// transport configuration.
    pub fn new(
        scope: AccountScope,
        base_url: Url,
        endpoint_class: EndpointClass,
        header: impl AsRef<str>,
        credential: ApiKeyCredential,
        config: TransportConfig,
    ) -> Result<Self, ClassifiedError> {
        let origin = base_url.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        endpoints
            .validate(&base_url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let header = HeaderName::from_bytes(header.as_ref().as_bytes())
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        // Validate the header class before any network request can be made.
        credential.authentication(&header)?;
        Self::build(
            scope,
            base_url,
            endpoints,
            ApiKeyAuthentication::Header(header),
            credential,
            config,
        )
    }

    /// Creates an exact-origin bearer-token client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for malformed endpoints or transport
    /// configuration.
    pub fn new_bearer(
        scope: AccountScope,
        base_url: Url,
        endpoint_class: EndpointClass,
        credential: ApiKeyCredential,
        config: TransportConfig,
    ) -> Result<Self, ClassifiedError> {
        let origin = base_url.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        endpoints
            .validate(&base_url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        credential.bearer_authentication()?;
        Self::build(
            scope,
            base_url,
            endpoints,
            ApiKeyAuthentication::Bearer,
            credential,
            config,
        )
    }

    /// Creates an exact-origin client using a vendor authorization scheme.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for malformed endpoints, an invalid scheme,
    /// or transport configuration.
    pub fn new_authorization_scheme(
        scope: AccountScope,
        base_url: Url,
        endpoint_class: EndpointClass,
        scheme: impl AsRef<str>,
        credential: ApiKeyCredential,
        config: TransportConfig,
    ) -> Result<Self, ClassifiedError> {
        let origin = base_url.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        endpoints
            .validate(&base_url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let scheme = scheme.as_ref();
        credential.authorization_scheme(scheme)?;
        Self::build(
            scope,
            base_url,
            endpoints,
            ApiKeyAuthentication::AuthorizationScheme(scheme.to_owned()),
            credential,
            config,
        )
    }

    fn build(
        scope: AccountScope,
        base_url: Url,
        endpoints: EndpointPolicy,
        authentication: ApiKeyAuthentication,
        credential: ApiKeyCredential,
        config: TransportConfig,
    ) -> Result<Self, ClassifiedError> {
        let transport =
            HttpTransport::new(endpoints, config).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            base_url,
            authentication,
            credential,
            config,
            transport,
        })
    }

    /// Exact provider/account scope owned by this client.
    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    /// Validated provider base URL used to build fixed paths.
    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Rebinds this client's authentication and account scope to one newly
    /// validated exact origin.
    ///
    /// This remains crate-private so only native provider adapters can apply
    /// their provider-specific discovery allowlist before cloning a secret.
    pub(crate) fn rebind(
        &self,
        base_url: Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let origin = base_url.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        endpoints
            .validate(&base_url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::build(
            self.scope.clone(),
            base_url,
            endpoints,
            self.authentication.clone(),
            self.credential.clone(),
            self.config,
        )
    }

    /// Resolves a provider-owned relative path under the validated base URL.
    ///
    /// # Errors
    ///
    /// Returns a stable API error when the path is not a relative URL or
    /// resolves outside the client's exact origin.
    pub fn url(&self, relative_path: &str) -> Result<Url, ClassifiedError> {
        if relative_path.starts_with('/')
            || relative_path.contains(['?', '#'])
            || relative_path.split('/').any(|component| component == "..")
            || Url::parse(relative_path).is_ok()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let url = self
            .base_url
            .join(relative_path)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if url.origin() != self.base_url.origin()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(url)
    }

    /// Performs one authenticated GET for the exact selected account.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for scope/source mismatches and the shared
    /// classified transport errors for network/provider failures.
    pub async fn get(
        &self,
        context: &ProviderContext,
        url: Url,
    ) -> Result<HttpResponse, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ApiKey {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let authentication = match &self.authentication {
            ApiKeyAuthentication::Bearer => self.credential.bearer_authentication()?,
            ApiKeyAuthentication::AuthorizationScheme(scheme) => {
                self.credential.authorization_scheme(scheme)?
            }
            ApiKeyAuthentication::Header(header) => self.credential.authentication(header)?,
        };
        let request = HttpRequest::get(url).authentication(authentication);
        self.transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())
    }

    /// Performs one authenticated JSON GET for the exact selected account.
    ///
    /// # Errors
    ///
    /// Returns stable classified configuration, network, and provider errors.
    pub async fn get_json(
        &self,
        context: &ProviderContext,
        url: Url,
    ) -> Result<HttpResponse, ClassifiedError> {
        let request = HttpRequest::get_json(url);
        self.send(context, request).await
    }

    /// Performs an authenticated JSON GET with bounded, non-secret metadata
    /// headers and an explicit JSON content type.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid/reserved metadata headers or a
    /// scope mismatch, plus classified transport failures.
    pub async fn get_json_with_public_headers(
        &self,
        context: &ProviderContext,
        url: Url,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, ClassifiedError> {
        let mut request = HttpRequest::get_json(url).empty_json_content_type();
        for (name, value) in headers {
            request = request
                .public_header(name, value)
                .map_err(|error| error.classified())?;
        }
        self.send(context, request).await
    }

    /// Performs one authenticated JSON GET while treating HTTP 404 as an
    /// explicit absence signal.
    ///
    /// # Errors
    ///
    /// Returns stable classified configuration, network, and provider errors
    /// for every outcome except HTTP 404.
    pub async fn get_optional_json(
        &self,
        context: &ProviderContext,
        url: Url,
    ) -> Result<Option<HttpResponse>, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ApiKey {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let authentication = match &self.authentication {
            ApiKeyAuthentication::Bearer => self.credential.bearer_authentication()?,
            ApiKeyAuthentication::AuthorizationScheme(scheme) => {
                self.credential.authorization_scheme(scheme)?
            }
            ApiKeyAuthentication::Header(header) => self.credential.authentication(header)?,
        };
        let request = HttpRequest::get_json(url).authentication(authentication);
        match self.transport.send(&request, context.cancellation()).await {
            Ok(response) => Ok(Some(response)),
            Err(crate::transport::TransportError::Api { status: 404 }) => Ok(None),
            Err(error) => Err(error.classified()),
        }
    }

    /// Performs one authenticated JSON POST for the exact selected account.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for scope/source mismatches or an oversized
    /// body and shared classified transport errors for network/provider
    /// failures.
    pub async fn post_json(
        &self,
        context: &ProviderContext,
        url: Url,
        body: Vec<u8>,
    ) -> Result<HttpResponse, ClassifiedError> {
        let request = HttpRequest::post_json(url, body).map_err(|error| error.classified())?;
        self.send(context, request).await
    }

    /// Performs one authenticated JSON POST with bounded, non-secret provider
    /// client-metadata headers.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid/reserved metadata headers,
    /// scope/source mismatches, or an oversized body, plus the shared
    /// classified transport errors for network/provider failures.
    pub async fn post_json_with_public_headers(
        &self,
        context: &ProviderContext,
        url: Url,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, ClassifiedError> {
        let mut request = HttpRequest::post_json(url, body).map_err(|error| error.classified())?;
        for (name, value) in headers {
            request = request
                .public_header(name, value)
                .map_err(|error| error.classified())?;
        }
        self.send(context, request).await
    }

    async fn send(
        &self,
        context: &ProviderContext,
        request: HttpRequest,
    ) -> Result<HttpResponse, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ApiKey {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let authentication = match &self.authentication {
            ApiKeyAuthentication::Bearer => self.credential.bearer_authentication()?,
            ApiKeyAuthentication::AuthorizationScheme(scheme) => {
                self.credential.authorization_scheme(scheme)?
            }
            ApiKeyAuthentication::Header(header) => self.credential.authentication(header)?,
        };
        let request = request.authentication(authentication);
        self.transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())
    }
}

impl Debug for FixedApiClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedApiClient")
            .field("scope", &self.scope)
            .field("scheme", &self.base_url.scheme())
            .field("host", &self.base_url.host_str())
            .field("path", &"<redacted>")
            .field(
                "authentication",
                &match &self.authentication {
                    ApiKeyAuthentication::Bearer => "bearer",
                    ApiKeyAuthentication::AuthorizationScheme(_) => "authorization-scheme",
                    ApiKeyAuthentication::Header(_) => "api-key-header",
                },
            )
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

fn clean_secret(raw: &str) -> Option<Zeroizing<String>> {
    let mut value = raw.trim();
    if value.len() >= 2 {
        let quoted = (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''));
        if quoted {
            value = &value[1..value.len() - 1];
        }
    }
    let value = value.trim();
    (!value.is_empty()).then(|| Zeroizing::new(value.to_owned()))
}

fn jwt_payload_is_object(value: &[u8]) -> bool {
    let mut parts = value.split(|byte| *byte == b'.');
    let Some(_header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(_signature) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || payload.is_empty() {
        return false;
    }
    let Some(decoded) = decode_base64_url(payload) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&decoded).is_ok_and(|value| value.is_object())
}

fn decode_base64_url(value: &[u8]) -> Option<Vec<u8>> {
    let unpadded_length = value
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(value.len());
    let padding = value.len().saturating_sub(unpadded_length);
    let remainder = unpadded_length % 4;
    if value[unpadded_length..].iter().any(|byte| *byte != b'=')
        || padding > 2
        || remainder == 1
        || (padding > 0 && padding != (4 - remainder) % 4)
    {
        return None;
    }
    let mut decoded = Vec::with_capacity(unpadded_length.saturating_mul(3) / 4 + 2);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in &value[..unpadded_length] {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((accumulator >> bits) & 0xff) as u8);
        }
        accumulator &= if bits == 0 { 0 } else { (1_u32 << bits) - 1 };
    }
    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return None;
    }
    Some(decoded)
}
