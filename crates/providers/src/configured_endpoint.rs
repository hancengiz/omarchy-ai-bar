//! Configured self-hosted endpoint validation and path construction.

use std::fmt::{self, Debug, Formatter};

use oab_domain::{ClassifiedError, ErrorKind};
use url::{Host, Url};

use crate::endpoint::{EndpointClass, classify_https_endpoint};

const MAX_PATH_SEGMENTS: usize = 32;
const MAX_PATH_SEGMENT_BYTES: usize = 1024;

/// HTTP authority granted to one provider-defined configured endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredHttpPolicy {
    /// Only HTTPS is accepted, including private and loopback HTTPS origins.
    HttpsOnly,
    /// HTTP is accepted only for an exact loopback origin.
    LoopbackHttp,
    /// HTTP is accepted for loopback and private-network/mDNS origins.
    PrivateNetworkHttp,
}

/// A credential-free configured base URL paired with its explicit class.
pub struct ConfiguredEndpoint {
    url: Url,
    class: EndpointClass,
}

impl ConfiguredEndpoint {
    /// Parses one explicit-scheme configured URL under the selected HTTP
    /// authority.
    ///
    /// # Errors
    ///
    /// Rejects missing/unsupported schemes, credentials, query/fragment data,
    /// public HTTP, and malformed authorities.
    pub fn parse(raw: &str, policy: ConfiguredHttpPolicy) -> Result<Self, ClassifiedError> {
        let raw = clean_setting(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        if !has_explicit_scheme(raw) {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let url = Url::parse(raw).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let class = match url.scheme() {
            "https" => {
                classify_https_endpoint(&url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            }
            "http" => classify_http_endpoint(&url, policy)?,
            _ => return Err(ClassifiedError::new(ErrorKind::Api)),
        };
        Ok(Self { url, class })
    }

    /// Validated configured URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Explicit class to pass to the exact-origin transport.
    #[must_use]
    pub const fn class(&self) -> EndpointClass {
        self.class
    }

    /// Appends provider-owned path segments, optionally replacing one exact
    /// terminal base segment such as `LiteLLM`'s `/v1`.
    ///
    /// # Errors
    ///
    /// Rejects excessive, empty, dot, slash-containing, or oversized segments.
    pub fn path(
        &self,
        strip_terminal: Option<&str>,
        segments: &[&str],
    ) -> Result<Url, ClassifiedError> {
        if segments.is_empty()
            || segments.len() > MAX_PATH_SEGMENTS
            || segments.iter().any(|segment| {
                segment.is_empty()
                    || segment.len() > MAX_PATH_SEGMENT_BYTES
                    || matches!(*segment, "." | "..")
                    || segment.contains(['/', '\\', '?', '#'])
            })
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let mut url = self.url.clone();
        let should_strip = strip_terminal.is_some_and(|terminal| {
            url.path_segments()
                .and_then(|mut values| values.rfind(|value| !value.is_empty()))
                == Some(terminal)
        });
        let mut path = url
            .path_segments_mut()
            .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
        path.pop_if_empty();
        if should_strip {
            path.pop();
        }
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }
}

impl Debug for ConfiguredEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredEndpoint")
            .field("url", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

/// Trims and unquotes environment/config-style settings.
#[must_use]
pub fn clean_setting(raw: &str) -> Option<&str> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = &value[1..value.len() - 1];
    }
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn classify_http_endpoint(
    url: &Url,
    policy: ConfiguredHttpPolicy,
) -> Result<EndpointClass, ClassifiedError> {
    let host = url
        .host()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if is_loopback(&host) {
        return match policy {
            ConfiguredHttpPolicy::HttpsOnly => Err(ClassifiedError::new(ErrorKind::Api)),
            ConfiguredHttpPolicy::LoopbackHttp | ConfiguredHttpPolicy::PrivateNetworkHttp => {
                Ok(EndpointClass::LoopbackDevelopment)
            }
        };
    }
    if policy == ConfiguredHttpPolicy::PrivateNetworkHttp && is_private_network(&host) {
        return Ok(EndpointClass::PrivateHttp);
    }
    Err(ClassifiedError::new(ErrorKind::Api))
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

fn is_private_network(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.');
            domain
                .rsplit_once('.')
                .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("local"))
        }
        Host::Ipv4(address) => address.is_private() || address.is_link_local(),
        Host::Ipv6(address) => {
            let first = address.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

fn has_explicit_scheme(raw: &str) -> bool {
    raw.find(':').is_some_and(|colon| {
        let scheme = &raw[..colon];
        !scheme.is_empty()
            && scheme.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                }
            })
    })
}
