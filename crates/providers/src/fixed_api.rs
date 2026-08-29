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

    fn authentication(&self, header: &HeaderName) -> Result<Authentication, ClassifiedError> {
        Authentication::api_key(header.as_str(), self.value.as_str().to_owned())
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
    header: HeaderName,
    credential: ApiKeyCredential,
    transport: HttpTransport,
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
        let transport =
            HttpTransport::new(endpoints, config).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            base_url,
            header,
            credential,
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
        self.base_url
            .join(relative_path)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))
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
        let authentication = self.credential.authentication(&self.header)?;
        let request = HttpRequest::get(url).authentication(authentication);
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
            .field("header", &self.header)
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
