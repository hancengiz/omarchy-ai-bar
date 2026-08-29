//! Exact-origin URL validation before any credential attachment.

use std::fmt::{self, Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use url::{Host, Url};

const MAX_APPROVED_ORIGINS: usize = 32;

/// Network authority granted to one exact configured origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointClass {
    /// Public DNS or globally routable IP with mandatory HTTPS.
    PublicHttps,
    /// Exact loopback origin used by isolated tests and local development.
    LoopbackDevelopment,
    /// Explicit private-network origin with mandatory HTTPS.
    PrivateHttps,
}

/// Selects the exact endpoint class for a configured HTTPS URL.
///
/// This preserves enterprise/private Azure-style endpoints while keeping the
/// transport's public, private, and loopback policies explicit.
///
/// # Errors
///
/// Returns an error for non-HTTPS, credential-bearing, or malformed URLs.
pub fn classify_https_endpoint(url: &Url) -> Result<EndpointClass, EndpointError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !is_https(url.scheme())
    {
        return Err(EndpointError::InvalidUrl);
    }
    let host = url.host().ok_or(EndpointError::InvalidUrl)?;
    if is_loopback_host(&host) {
        Ok(EndpointClass::LoopbackDevelopment)
    } else if is_public_host(&host) {
        Ok(EndpointClass::PublicHttps)
    } else {
        Ok(EndpointClass::PrivateHttps)
    }
}

/// Safe URL-policy failures. Variants deliberately carry no raw URL text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EndpointError {
    /// Origin or request URL was syntactically invalid.
    #[error("endpoint URL is invalid")]
    InvalidUrl,
    /// Origin declaration contained path, query, fragment, or user information.
    #[error("approved origin is not a bare credential-free origin")]
    InvalidOrigin,
    /// The scheme is incompatible with the typed network class.
    #[error("endpoint transport scheme is not allowed")]
    InsecureScheme,
    /// Public/private/loopback classification did not match the host.
    #[error("endpoint host is not allowed by its network class")]
    DisallowedHost,
    /// The request did not match an exact approved origin.
    #[error("endpoint origin is not approved")]
    UnapprovedOrigin,
    /// URL user information or fragment was present.
    #[error("endpoint URL contains forbidden credentials or fragments")]
    ForbiddenUrlComponent,
    /// A query parameter could carry authentication material.
    #[error("authentication material is forbidden in endpoint query parameters")]
    SensitiveQuery,
    /// The configured origin list was empty or exceeded its bound.
    #[error("approved endpoint origin count is invalid")]
    InvalidOriginCount,
}

/// Immutable exact-origin policy for one provider/account transport.
#[derive(Debug, Clone)]
pub struct EndpointPolicy {
    origins: Vec<ApprovedOrigin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovedOrigin {
    scheme: String,
    host: String,
    port: u16,
    class: EndpointClass,
}

impl EndpointPolicy {
    /// Parses and validates a bounded exact-origin allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] for empty/excessive lists, malformed origins,
    /// insecure public/private origins, or mismatched network classifications.
    pub fn new<I, S>(origins: I) -> Result<Self, EndpointError>
    where
        I: IntoIterator<Item = (S, EndpointClass)>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for (origin, class) in origins {
            if parsed.len() == MAX_APPROVED_ORIGINS {
                return Err(EndpointError::InvalidOriginCount);
            }
            let origin = Url::parse(origin.as_ref()).map_err(|_| EndpointError::InvalidUrl)?;
            parsed.push(ApprovedOrigin::parse(&origin, class)?);
        }
        if parsed.is_empty() {
            return Err(EndpointError::InvalidOriginCount);
        }
        parsed.sort_by(|left, right| {
            (&left.scheme, &left.host, left.port).cmp(&(&right.scheme, &right.host, right.port))
        });
        parsed.dedup_by(|left, right| {
            left.scheme == right.scheme && left.host == right.host && left.port == right.port
        });
        Ok(Self { origins: parsed })
    }

    /// Validates a complete request or redirect target without attaching credentials.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] for forbidden URL components, sensitive query
    /// keys, or any origin not present in this exact allowlist.
    pub fn validate(&self, url: &Url) -> Result<ValidatedEndpoint, EndpointError> {
        validate_request_components(url)?;
        let scheme = url.scheme();
        let host = url.host_str().ok_or(EndpointError::InvalidUrl)?;
        let port = normalized_port(url)?;
        let approved = self.origins.iter().find(|origin| {
            origin.scheme == scheme && origin.host.eq_ignore_ascii_case(host) && origin.port == port
        });
        let Some(approved) = approved else {
            return Err(EndpointError::UnapprovedOrigin);
        };
        validate_host_class(url, approved.class)?;
        Ok(ValidatedEndpoint {
            url: url.clone(),
            class: approved.class,
        })
    }
}

impl ApprovedOrigin {
    fn parse(url: &Url, class: EndpointClass) -> Result<Self, EndpointError> {
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(EndpointError::InvalidOrigin);
        }
        validate_scheme(url.scheme(), class)?;
        validate_host_class(url, class)?;
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host: url
                .host_str()
                .ok_or(EndpointError::InvalidUrl)?
                .to_ascii_lowercase(),
            port: normalized_port(url)?,
            class,
        })
    }
}

/// Endpoint token proving policy validation occurred before request construction.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedEndpoint {
    url: Url,
    class: EndpointClass,
}

impl ValidatedEndpoint {
    /// Returns the validated URL for the HTTP client only.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Typed network class granted to this exact origin.
    #[must_use]
    pub const fn class(&self) -> EndpointClass {
        self.class
    }
}

impl Debug for ValidatedEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedEndpoint")
            .field("scheme", &self.url.scheme())
            .field("host", &self.url.host_str())
            .field("port", &self.url.port_or_known_default())
            .field("class", &self.class)
            .field("path", &"<redacted>")
            .field("query", &"<redacted>")
            .finish()
    }
}

fn validate_request_components(url: &Url) -> Result<(), EndpointError> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(EndpointError::ForbiddenUrlComponent);
    }
    for (name, _value) in url.query_pairs() {
        let normalized = name.to_ascii_lowercase().replace('-', "_");
        if matches!(
            normalized.as_str(),
            "api_key"
                | "apikey"
                | "key"
                | "token"
                | "access_token"
                | "auth"
                | "authorization"
                | "bearer"
                | "client_secret"
                | "credential"
                | "credentials"
                | "jwt"
                | "secret"
                | "session_key"
                | "session_token"
                | "password"
                | "sig"
                | "signature"
        ) {
            return Err(EndpointError::SensitiveQuery);
        }
    }
    Ok(())
}

const fn validate_scheme(scheme: &str, class: EndpointClass) -> Result<(), EndpointError> {
    match class {
        EndpointClass::PublicHttps | EndpointClass::PrivateHttps if is_https(scheme) => Ok(()),
        EndpointClass::LoopbackDevelopment if is_https(scheme) || is_http(scheme) => Ok(()),
        _ => Err(EndpointError::InsecureScheme),
    }
}

const fn is_https(scheme: &str) -> bool {
    matches!(scheme.as_bytes(), [b'h', b't', b't', b'p', b's'])
}

const fn is_http(scheme: &str) -> bool {
    matches!(scheme.as_bytes(), [b'h', b't', b't', b'p'])
}

fn validate_host_class(url: &Url, class: EndpointClass) -> Result<(), EndpointError> {
    validate_scheme(url.scheme(), class)?;
    let host = url.host().ok_or(EndpointError::InvalidUrl)?;
    let allowed = match class {
        EndpointClass::PublicHttps => is_public_host(&host),
        EndpointClass::LoopbackDevelopment => is_loopback_host(&host),
        EndpointClass::PrivateHttps => !is_public_host(&host) && !is_loopback_host(&host),
    };
    if allowed {
        Ok(())
    } else {
        Err(EndpointError::DisallowedHost)
    }
}

fn is_public_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let domain = domain.to_ascii_lowercase();
            domain.contains('.')
                && domain != "localhost"
                && !ends_with_dns_label(&domain, "localhost")
                && !ends_with_dns_label(&domain, "local")
        }
        Host::Ipv4(address) => is_public_ipv4(*address),
        Host::Ipv6(address) => is_public_ipv6(*address),
    }
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            domain.eq_ignore_ascii_case("localhost") || ends_with_dns_label(domain, "localhost")
        }
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

fn ends_with_dns_label(domain: &str, label: &str) -> bool {
    domain
        .rsplit_once('.')
        .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case(label))
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
        || address.is_unspecified()
        || address.octets()[0] == 0)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn normalized_port(url: &Url) -> Result<u16, EndpointError> {
    url.port_or_known_default().ok_or(EndpointError::InvalidUrl)
}
