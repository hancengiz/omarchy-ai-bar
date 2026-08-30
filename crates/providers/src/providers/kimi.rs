//! Native Kimi Code API, CLI OAuth, and web-session quota adapter.

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, NamedRateWindow, ProviderId, RateWindow,
    Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rusqlite::types::ValueRef;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptionError, ChromiumCookieDecryptor,
    import_browser_cookies_merging_chromium_stores_with_decryptor,
};
use crate::browser_profile::{BrowserKind, BrowserProfileDiscovery};
use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieImportOrder, CookieJar, CookieSourceId, CookieUrlPolicy, ValidatedCookieUrl,
};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, count_percent, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig, TransportError,
};

const CODE_API_ORIGIN: &str = "https://api.kimi.com";
const WEB_ORIGIN: &str = "https://www.kimi.com";
const WEB_USAGE_PATH: &str = "/apiv2/kimi.gateway.billing.v1.BillingService/GetUsages";
const SUBSCRIPTION_PATH: &str =
    "/apiv2/kimi.gateway.membership.v2.MembershipService/GetSubscriptionStats";
const CODE_API_KEY_ENV: &str = "KIMI_CODE_API_KEY";
const CODE_API_BASE_ENV: &str = "KIMI_CODE_BASE_URL";
const CODE_HOME_ENV: &str = "KIMI_CODE_HOME";
const OAUTH_HOST_ENVS: [&str; 2] = ["KIMI_CODE_OAUTH_HOST", "KIMI_OAUTH_HOST"];
const DESKTOP_ROOT_ENV: &str = "KIMI_DESKTOP_COOKIE_ROOT";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_JSON_AGGREGATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_FILE_BYTES: u64 = 256 * 1024;
const MAX_CREDENTIAL_FILE_BYTES_USIZE: usize = 256 * 1024;
const MAX_DEVICE_FILE_BYTES: u64 = 4 * 1024;
const MAX_DEVICE_FILE_BYTES_USIZE: usize = 4 * 1024;
const MAX_TIMEZONE_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_BROWSER_PROFILES: usize = 128;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_DESKTOP_ROWS: usize = 64;
const MAX_DESKTOP_FIELD_BYTES: usize = 64 * 1024;
const WEEKLY_MINUTES: i64 = 7 * 24 * 60;
const MONTHLY_SENTINEL_MINUTES: i64 = 30 * 24 * 60;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SUBSCRIPTION_GRACE: Duration = Duration::from_secs(2);
const WEB_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);

/// Validated Kimi Code and Kimi web endpoints.
pub struct KimiRouteSet {
    code_usage: Url,
    code_class: EndpointClass,
    web_usage: Url,
    subscription: Url,
    web_class: EndpointClass,
}

impl KimiRouteSet {
    fn production(code_base: &Url, code_class: EndpointClass) -> Result<Self, ClassifiedError> {
        let code_usage = code_usage_endpoint(code_base, code_class)?;
        let web_origin = Url::parse(WEB_ORIGIN).map_err(|_| api_error())?;
        Self::from_parts(
            code_usage,
            code_class,
            &web_origin,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates exact loopback routes for isolated HTTP tests.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback origins, URL credentials, and non-root origins.
    #[doc(hidden)]
    pub fn loopback(code_base: &Url, web_origin: &Url) -> Result<Self, ClassifiedError> {
        let code_usage = code_usage_endpoint(code_base, EndpointClass::LoopbackDevelopment)?;
        Self::from_parts(
            code_usage,
            EndpointClass::LoopbackDevelopment,
            web_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_parts(
        code_usage: Url,
        code_class: EndpointClass,
        web_origin: &Url,
        web_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        validate_root_origin(web_origin, web_class)?;
        if web_class == EndpointClass::PublicHttps && web_origin.as_str() != "https://www.kimi.com/"
        {
            return Err(api_error());
        }
        validate_request_url(&code_usage, code_class)?;
        let web_usage = with_fixed_path(web_origin, WEB_USAGE_PATH);
        let subscription = with_fixed_path(web_origin, SUBSCRIPTION_PATH);
        validate_request_url(&web_usage, web_class)?;
        validate_request_url(&subscription, web_class)?;
        Ok(Self {
            code_usage,
            code_class,
            web_usage,
            subscription,
            web_class,
        })
    }

    fn code_transport(&self) -> Result<HttpTransport, ClassifiedError> {
        exact_transport(&self.code_usage, self.code_class, REQUEST_TIMEOUT)
    }

    fn web_transport(&self) -> Result<HttpTransport, ClassifiedError> {
        exact_transport(&self.web_usage, self.web_class, REQUEST_TIMEOUT)
    }
}

impl Debug for KimiRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KimiRouteSet")
            .field("code_usage", &"<redacted>")
            .field("code_class", &self.code_class)
            .field("web_usage", &"<redacted>")
            .field("subscription", &"<redacted>")
            .field("web_class", &self.web_class)
            .finish()
    }
}

/// Read-only fresh OAuth credential discovered from the Kimi Code CLI.
pub struct KimiCliCredential {
    credential: KimiCredential,
    identity: KimiCliIdentity,
    credential_path: PathBuf,
}

impl KimiCliCredential {
    /// Reads a fresh CLI access token without refreshing or rewriting any CLI file.
    ///
    /// CLI credential reuse is disabled whenever a Code API or OAuth endpoint
    /// override is present, preventing a first-party token from reaching a
    /// caller-selected host.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, permission, parse, or endpoint errors.
    pub fn resolve_at(
        environment: &BTreeMap<String, String>,
        now: Timestamp,
    ) -> Result<Self, ClassifiedError> {
        if has_cli_endpoint_override(environment) {
            return Err(api_error());
        }
        let home = code_home(environment)?;
        let credential_path = home.join("credentials/kimi-code.json");
        validate_path(&credential_path)?;
        let mut bytes = read_bounded_file(
            &credential_path,
            MAX_CREDENTIAL_FILE_BYTES,
            MAX_CREDENTIAL_FILE_BYTES_USIZE,
        )?;
        let document: KimiCliDocument =
            serde_json::from_slice(&bytes).map_err(|_| parse_error())?;
        bytes.zeroize();
        let expires_at = document
            .expires_at
            .filter(|value| value.is_finite())
            .ok_or_else(auth_error)?;
        let fresh_after = now
            .unix_timestamp()
            .checked_add(60)
            .ok_or_else(parse_error)?;
        #[expect(
            clippy::cast_precision_loss,
            reason = "valid Unix timestamps are far below f64's exact-integer ceiling"
        )]
        if expires_at <= fresh_after as f64 {
            return Err(auth_error());
        }
        let credential =
            KimiCredential::from_zeroizing(document.access_token.0).map_err(|_| auth_error())?;
        let identity = KimiCliIdentity::resolve(environment, &home)?;
        Ok(Self {
            credential,
            identity,
            credential_path,
        })
    }

    /// Exact selected file for path-only diagnostics.
    #[must_use]
    pub fn credential_path(&self) -> &Path {
        &self.credential_path
    }
}

impl Debug for KimiCliCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KimiCliCredential")
            .field("credential", &"<redacted>")
            .field("identity", &self.identity)
            .field("credential_path", &"<redacted>")
            .finish()
    }
}

/// Public-safe Kimi Code CLI identity metadata.
pub struct KimiCliIdentity {
    headers: Vec<(&'static str, String)>,
}

impl KimiCliIdentity {
    fn resolve(
        environment: &BTreeMap<String, String>,
        home: &Path,
    ) -> Result<Self, ClassifiedError> {
        let device_name = environment
            .get("HOSTNAME")
            .and_then(|value| safe_ascii_header(value))
            .unwrap_or_else(|| "unknown".to_owned());
        let device_id_path = home.join("device_id");
        validate_path(&device_id_path)?;
        let device_id = match read_bounded_file(
            &device_id_path,
            MAX_DEVICE_FILE_BYTES,
            MAX_DEVICE_FILE_BYTES_USIZE,
        ) {
            Ok(mut bytes) => {
                let parsed = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(safe_ascii_header)
                    .filter(|value| value.len() <= 256);
                bytes.zeroize();
                parsed.unwrap_or_else(|| fallback_device_id(home, &device_name))
            }
            Err(_) => fallback_device_id(home, &device_name),
        };
        let version = env!("CARGO_PKG_VERSION").to_owned();
        let os_version = "linux".to_owned();
        let model = format!("Linux {os_version} {}", std::env::consts::ARCH);
        Ok(Self {
            headers: vec![
                ("user-agent", format!("omarchy-ai-bar/{version}")),
                ("x-msh-platform", "kimi_code_cli".to_owned()),
                ("x-msh-version", version),
                ("x-msh-device-name", device_name),
                ("x-msh-device-model", model),
                ("x-msh-os-version", os_version),
                ("x-msh-device-id", device_id),
            ],
        })
    }

    /// Builds deterministic CLI identity headers for isolated tests.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or unbounded header values.
    #[doc(hidden)]
    pub fn for_test(device_name: &str, device_id: &str) -> Result<Self, ClassifiedError> {
        let device_name = safe_ascii_header(device_name).ok_or_else(api_error)?;
        let device_id = safe_ascii_header(device_id).ok_or_else(api_error)?;
        Ok(Self {
            headers: vec![
                ("user-agent", "omarchy-ai-bar/test".to_owned()),
                ("x-msh-platform", "kimi_code_cli".to_owned()),
                ("x-msh-version", "test".to_owned()),
                ("x-msh-device-name", device_name),
                ("x-msh-device-model", "Linux test x86_64".to_owned()),
                ("x-msh-os-version", "test".to_owned()),
                ("x-msh-device-id", device_id),
            ],
        })
    }
}

impl Debug for KimiCliIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KimiCliIdentity")
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// Safe read-only Kimi Desktop Chromium cookie-store access.
pub struct KimiDesktopCookieStore;

impl KimiDesktopCookieStore {
    /// Reads the newest usable `kimi-auth` cookie from an explicit profile root.
    ///
    /// The root must contain `Cookies`. The shared SQLite snapshot layer copies
    /// bounded database/WAL state into private staging and never opens the live
    /// application database for writing. Encrypted values are delegated to the
    /// injected Linux Chromium decryptor.
    ///
    /// # Errors
    ///
    /// Returns only stable path-free local-data errors.
    pub fn load(
        profile_root: &Path,
        decryptor: &dyn ChromiumCookieDecryptor,
    ) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
        validate_path(profile_root)?;
        let snapshot = match ReadOnlySqliteSnapshot::open(profile_root, "Cookies") {
            Ok(snapshot) => snapshot,
            Err(SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot) => {
                return Ok(None);
            }
            Err(_) => return Err(parse_error()),
        };
        let database_version = desktop_database_version(snapshot.connection())?;
        let mut statement = snapshot
            .connection()
            .prepare(
                "SELECT host_key, value, encrypted_value FROM cookies \
                 WHERE name = 'kimi-auth' \
                 AND host_key IN ('www.kimi.com', '.www.kimi.com', '.kimi.com', 'kimi.com') \
                 ORDER BY last_access_utc DESC, rowid DESC LIMIT ?",
            )
            .map_err(|_| parse_error())?;
        let limit = i64::try_from(MAX_DESKTOP_ROWS).map_err(|_| parse_error())?;
        let mut rows = statement.query([limit]).map_err(|_| parse_error())?;
        while let Some(row) = rows.next().map_err(|_| parse_error())? {
            let host = sqlite_text(row.get_ref(0).map_err(|_| parse_error())?)?;
            let plaintext = sqlite_text(row.get_ref(1).map_err(|_| parse_error())?)?;
            let encrypted = sqlite_blob(row.get_ref(2).map_err(|_| parse_error())?)?;
            if !plaintext.is_empty() && !encrypted.is_empty() {
                return Err(parse_error());
            }
            let token = if !plaintext.is_empty() {
                Zeroizing::new(plaintext)
            } else if !encrypted.is_empty() {
                match decryptor.decrypt(BrowserKind::Chromium, &encrypted) {
                    Ok(value) => desktop_decrypted_value(&host, database_version, value)?,
                    Err(ChromiumCookieDecryptionError::Unavailable) => continue,
                    Err(ChromiumCookieDecryptionError::Failed) => return Err(parse_error()),
                }
            } else {
                continue;
            };
            if validate_cookie_token(token.as_str()).is_ok() {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }

    /// Resolves an explicit Linux Desktop cookie root from
    /// `KIMI_DESKTOP_COOKIE_ROOT`.
    ///
    /// No implicit path is used because the pinned upstream application has no
    /// documented Linux Desktop cookie location.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when the explicit root is absent.
    pub fn root_from_environment(
        environment: &BTreeMap<String, String>,
    ) -> Result<PathBuf, ClassifiedError> {
        let root = environment
            .get(DESKTOP_ROOT_ENV)
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let root = PathBuf::from(root);
        validate_path(&root)?;
        Ok(root)
    }
}

/// Native Kimi provider permanently bound to one account and source.
pub struct KimiProvider {
    scope: AccountScope,
    source: ProviderSource,
    mode: KimiMode,
    routes: KimiRouteSet,
    code_transport: HttpTransport,
    web_transport: HttpTransport,
    enrichment_sessions: Vec<WebSession>,
    subscription_grace: Duration,
    web_timezone: String,
}

enum KimiMode {
    Code {
        credential: KimiCredential,
        identity: Option<KimiCliIdentity>,
    },
    Web {
        sessions: Vec<WebSession>,
    },
}

struct WebSession {
    token: Zeroizing<String>,
}

struct KimiCredential(Zeroizing<String>);

impl KimiCredential {
    fn new(raw: &str) -> Result<Self, ClassifiedError> {
        let value = cleaned_secret(raw)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::from_zeroizing(Zeroizing::new(value.to_owned()))
    }

    fn from_zeroizing(mut value: Zeroizing<String>) -> Result<Self, ClassifiedError> {
        let cleaned = cleaned_secret(value.as_str())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        if cleaned.len() > MAX_TOKEN_BYTES || cleaned.contains(['\r', '\n']) {
            return Err(parse_error());
        }
        if cleaned.len() != value.len() {
            let replacement = Zeroizing::new(cleaned.to_owned());
            value.zeroize();
            value = replacement;
        }
        Authentication::bearer(value.as_str().to_owned()).map_err(classify_transport)?;
        Ok(Self(value))
    }

    fn authentication(&self) -> Result<Authentication, ClassifiedError> {
        Authentication::bearer(self.0.as_str().to_owned()).map_err(classify_transport)
    }
}

impl Debug for KimiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("KimiCredential(<redacted>)")
    }
}

impl Debug for WebSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSession(<redacted>)")
    }
}

impl KimiProvider {
    /// Creates a production Kimi Code API-key adapter from environment values.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential or HTTPS endpoint errors.
    pub fn new_api(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let raw = environment
            .get(CODE_API_KEY_ENV)
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let credential = KimiCredential::new(raw)?;
        let (base, class) = configured_code_base(environment)?;
        let routes = KimiRouteSet::production(&base, class)?;
        let source = if environment
            .get(CODE_API_BASE_ENV)
            .and_then(|value| clean_setting(value))
            .is_some()
        {
            ProviderSource::ConfigurableEndpoint
        } else {
            ProviderSource::ApiKey
        };
        Self::build_code(scope, source, credential, None, routes)
    }

    /// Creates a production adapter from fresh read-only Kimi Code CLI OAuth state.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, permission, parse, scope, or endpoint errors.
    pub fn new_cli(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
        now: Timestamp,
    ) -> Result<Self, ClassifiedError> {
        let cli = KimiCliCredential::resolve_at(environment, now)?;
        let base = Url::parse(CODE_API_ORIGIN).map_err(|_| api_error())?;
        let routes = KimiRouteSet::production(&base, EndpointClass::PublicHttps)?;
        Self::build_code(
            scope,
            ProviderSource::Cli,
            cli.credential,
            Some(cli.identity),
            routes,
        )
    }

    /// Creates a production web adapter from a bare JWT, Cookie header, or cURL capture.
    ///
    /// # Errors
    ///
    /// Returns stable capture, credential, scope, or endpoint errors.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        let base = Url::parse(CODE_API_ORIGIN).map_err(|_| api_error())?;
        let routes = KimiRouteSet::production(&base, EndpointClass::PublicHttps)?;
        Self::build_web(
            scope,
            ProviderSource::ManualCookie,
            vec![WebSession {
                token: parse_web_token(raw)?,
            }],
            routes,
        )
    }

    /// Resolves manual web input with `KIMI_MANUAL_COOKIE` before `KIMI_AUTH_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when neither explicit environment value exists.
    pub fn new_manual_from_environment(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let base = Url::parse(CODE_API_ORIGIN).map_err(|_| api_error())?;
        let routes = KimiRouteSet::production(&base, EndpointClass::PublicHttps)?;
        Self::build_web(
            scope,
            ProviderSource::ManualCookie,
            vec![WebSession {
                token: manual_environment_token(environment)?,
            }],
            routes,
        )
    }

    /// Creates a production adapter from ordered Linux Chromium/Firefox profiles.
    ///
    /// # Errors
    ///
    /// Returns stable missing, bounded local-data, decryption, scope, or endpoint errors.
    pub fn new_browser(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let base = Url::parse(CODE_API_ORIGIN).map_err(|_| api_error())?;
        let routes = KimiRouteSet::production(&base, EndpointClass::PublicHttps)?;
        let sessions = browser_sessions(discovery, decryptor, &routes, now)?;
        Self::build_web(scope, ProviderSource::BrowserSession, sessions, routes)
    }

    /// Creates an injected-route browser adapter for deterministic profile tests.
    ///
    /// # Errors
    ///
    /// Returns stable missing, bounded local-data, decryption, scope, or route errors.
    #[doc(hidden)]
    pub fn from_browser_routes(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
        routes: KimiRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let sessions = browser_sessions(discovery, decryptor, &routes, now)?;
        Self::build_web(scope, ProviderSource::BrowserSession, sessions, routes)
    }

    /// Creates a production adapter from an explicit safe Desktop cookie root.
    ///
    /// # Errors
    ///
    /// Returns stable missing, local-data, decryption, scope, or endpoint errors.
    pub fn new_desktop(
        scope: AccountScope,
        profile_root: &Path,
        decryptor: &dyn ChromiumCookieDecryptor,
    ) -> Result<Self, ClassifiedError> {
        let token = KimiDesktopCookieStore::load(profile_root, decryptor)?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let base = Url::parse(CODE_API_ORIGIN).map_err(|_| api_error())?;
        let routes = KimiRouteSet::production(&base, EndpointClass::PublicHttps)?;
        Self::build_web(
            scope,
            ProviderSource::LocalData,
            vec![WebSession { token }],
            routes,
        )
    }

    /// Creates an injected exact-route API or CLI adapter for HTTP tests.
    ///
    /// # Errors
    ///
    /// Returns stable credential, scope, or route errors.
    #[doc(hidden)]
    pub fn from_code_token_routes(
        scope: AccountScope,
        raw: &str,
        source: ProviderSource,
        identity: Option<KimiCliIdentity>,
        routes: KimiRouteSet,
    ) -> Result<Self, ClassifiedError> {
        if !matches!(
            source,
            ProviderSource::ApiKey | ProviderSource::ConfigurableEndpoint | ProviderSource::Cli
        ) {
            return Err(api_error());
        }
        let credential = KimiCredential::new(raw)?;
        Self::build_code(scope, source, credential, identity, routes)
    }

    /// Creates an injected exact-route web adapter for HTTP tests.
    ///
    /// # Errors
    ///
    /// Returns stable capture, source, scope, or route errors.
    #[doc(hidden)]
    pub fn from_manual_routes(
        scope: AccountScope,
        raw: &str,
        source: ProviderSource,
        routes: KimiRouteSet,
    ) -> Result<Self, ClassifiedError> {
        if !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::LocalData
        ) {
            return Err(api_error());
        }
        Self::build_web(
            scope,
            source,
            vec![WebSession {
                token: parse_web_token(raw)?,
            }],
            routes,
        )
    }

    /// Creates an injected exact-route adapter using manual environment precedence.
    ///
    /// # Errors
    ///
    /// Returns stable credential, capture, scope, or route errors.
    #[doc(hidden)]
    pub fn from_manual_environment_routes(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
        routes: KimiRouteSet,
    ) -> Result<Self, ClassifiedError> {
        Self::build_web(
            scope,
            ProviderSource::ManualCookie,
            vec![WebSession {
                token: manual_environment_token(environment)?,
            }],
            routes,
        )
    }

    fn build_code(
        scope: AccountScope,
        source: ProviderSource,
        credential: KimiCredential,
        identity: Option<KimiCliIdentity>,
        routes: KimiRouteSet,
    ) -> Result<Self, ClassifiedError> {
        validate_provider_scope(&scope, source)?;
        let code_transport = routes.code_transport()?;
        let web_transport = routes.web_transport()?;
        Ok(Self {
            scope,
            source,
            mode: KimiMode::Code {
                credential,
                identity,
            },
            routes,
            code_transport,
            web_transport,
            enrichment_sessions: Vec::new(),
            subscription_grace: SUBSCRIPTION_GRACE,
            web_timezone: local_web_timezone(),
        })
    }

    fn build_web(
        scope: AccountScope,
        source: ProviderSource,
        sessions: Vec<WebSession>,
        routes: KimiRouteSet,
    ) -> Result<Self, ClassifiedError> {
        validate_provider_scope(&scope, source)?;
        if sessions.is_empty() || sessions.len() > MAX_BROWSER_SESSIONS {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let code_transport = routes.code_transport()?;
        let web_transport = routes.web_transport()?;
        Ok(Self {
            scope,
            source,
            mode: KimiMode::Web { sessions },
            routes,
            code_transport,
            web_transport,
            enrichment_sessions: Vec::new(),
            subscription_grace: SUBSCRIPTION_GRACE,
            web_timezone: local_web_timezone(),
        })
    }

    /// Adds one explicit web JWT used only for optional subscription enrichment.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error for invalid token/capture input.
    pub fn with_web_enrichment(mut self, raw: &str) -> Result<Self, ClassifiedError> {
        if !matches!(self.mode, KimiMode::Code { .. }) {
            return Err(api_error());
        }
        self.enrichment_sessions = vec![WebSession {
            token: resolved_web_token(raw)?,
        }];
        Ok(self)
    }

    /// Adds ordered Linux browser sessions for optional Code API/CLI enrichment.
    ///
    /// # Errors
    ///
    /// Returns stable missing, bounded local-data, or decryption errors.
    pub fn with_browser_enrichment(
        mut self,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        if !matches!(self.mode, KimiMode::Code { .. }) {
            return Err(api_error());
        }
        self.enrichment_sessions = browser_sessions(discovery, decryptor, &self.routes, now)?;
        Ok(self)
    }

    /// Overrides only the optional subscription join budget for deterministic tests.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive budgets.
    #[doc(hidden)]
    pub fn with_subscription_grace(mut self, grace: Duration) -> Result<Self, ClassifiedError> {
        if grace.is_zero() || grace > REQUEST_TIMEOUT {
            return Err(api_error());
        }
        self.subscription_grace = grace;
        Ok(self)
    }

    /// Overrides the bounded IANA-style web timezone for deterministic tests.
    ///
    /// # Errors
    ///
    /// Rejects values that cannot safely be emitted as one public header.
    #[doc(hidden)]
    pub fn with_web_timezone(mut self, timezone: &str) -> Result<Self, ClassifiedError> {
        self.web_timezone = validated_timezone(timezone).ok_or_else(api_error)?;
        Ok(self)
    }

    /// Fetches one deterministic sample at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable scope, auth, network, status, cancellation, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        match &self.mode {
            KimiMode::Code {
                credential,
                identity,
            } => {
                let snapshot = self
                    .fetch_code(
                        context.cancellation(),
                        credential,
                        identity.as_ref(),
                        fetched_at,
                    )
                    .await?;
                snapshot_to_sample(
                    self.scope.clone(),
                    fetched_at,
                    snapshot,
                    source_strategy(self.source),
                )
            }
            KimiMode::Web { sessions } => {
                let snapshot = self
                    .fetch_web_sessions(context.cancellation(), sessions, fetched_at)
                    .await?;
                snapshot_to_sample(
                    self.scope.clone(),
                    fetched_at,
                    snapshot,
                    source_strategy(self.source),
                )
            }
        }
    }

    async fn fetch_code(
        &self,
        cancellation: &CancellationToken,
        credential: &KimiCredential,
        identity: Option<&KimiCliIdentity>,
        fetched_at: Timestamp,
    ) -> Result<KimiSnapshot, ClassifiedError> {
        let authentication = credential_bearer(credential)?;
        let mut request = HttpRequest::get_json(self.routes.code_usage.clone())
            .authentication(authentication)
            .accepted_statuses(&[400, 401, 403])
            .map_err(classify_transport)?;
        if let Some(identity) = identity {
            for (name, value) in &identity.headers {
                request = request
                    .public_header(*name, value)
                    .map_err(classify_transport)?;
            }
        }
        let response = self
            .code_transport
            .send(&request, cancellation)
            .await
            .map_err(classify_transport)?;
        classify_code_status(response.status())?;
        let mut snapshot = parse_code_response(response.body())?;
        if !self.enrichment_sessions.is_empty() {
            match tokio::time::timeout(self.subscription_grace, async {
                for session in &self.enrichment_sessions {
                    match self.fetch_subscription(cancellation, session).await {
                        Ok(Some(subscription)) => return Ok(Some(subscription)),
                        Err(error) if cancellation.is_cancelled() => return Err(error),
                        Ok(None) | Err(_) => {}
                    }
                }
                Ok(None)
            })
            .await
            {
                Ok(Ok(Some(subscription))) => snapshot.subscription = Some(subscription),
                Ok(Err(error)) if cancellation.is_cancelled() => return Err(error),
                Ok(Ok(None) | Err(_)) | Err(_) => {}
            }
            if cancellation.is_cancelled() {
                return Err(network_error());
            }
        }
        snapshot.fetched_at = fetched_at;
        Ok(snapshot)
    }

    async fn fetch_web_sessions(
        &self,
        cancellation: &CancellationToken,
        sessions: &[WebSession],
        fetched_at: Timestamp,
    ) -> Result<KimiSnapshot, ClassifiedError> {
        let mut last_error = None;
        for session in sessions {
            match self
                .fetch_web_session(cancellation, session, fetched_at)
                .await
            {
                Ok(snapshot) => return Ok(snapshot),
                Err(error) => {
                    let retry_session = self.source == ProviderSource::BrowserSession
                        && matches!(
                            error.kind(),
                            ErrorKind::AuthenticationExpired
                                | ErrorKind::PermissionDenied
                                | ErrorKind::Api
                        );
                    if !retry_session {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    async fn fetch_web_session(
        &self,
        cancellation: &CancellationToken,
        session: &WebSession,
        fetched_at: Timestamp,
    ) -> Result<KimiSnapshot, ClassifiedError> {
        let required = self.fetch_required_web(cancellation, session);
        let optional = self.fetch_subscription(cancellation, session);
        tokio::pin!(required);
        tokio::pin!(optional);
        let grace = tokio::time::sleep(self.subscription_grace);
        tokio::pin!(grace);
        let mut subscription = None;
        let mut optional_finished = false;
        let required_result = loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(network_error()),
                result = &mut required => break result,
                () = &mut grace, if !optional_finished => {
                    optional_finished = true;
                }
                result = &mut optional, if !optional_finished => {
                    optional_finished = true;
                    if let Ok(value) = result {
                        subscription = value;
                    }
                }
            }
        }?;
        if !optional_finished {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(network_error()),
                () = &mut grace => {}
                result = &mut optional => {
                    if let Ok(value) = result {
                        subscription = value;
                    }
                }
            }
        }
        Ok(KimiSnapshot {
            weekly: required_result.weekly,
            rate_limit: required_result.rate_limit,
            subscription,
            fetched_at,
        })
    }

    async fn fetch_required_web(
        &self,
        cancellation: &CancellationToken,
        session: &WebSession,
    ) -> Result<RequiredUsage, ClassifiedError> {
        let request = web_request(
            self.routes.web_usage.clone(),
            session,
            br#"{"scope":["FEATURE_CODING"]}"#.to_vec(),
            &self.web_timezone,
        )?;
        let response = self
            .web_transport
            .send(&request, cancellation)
            .await
            .map_err(classify_transport)?;
        classify_web_status(response.status())?;
        parse_web_response(response.body())
    }

    async fn fetch_subscription(
        &self,
        cancellation: &CancellationToken,
        session: &WebSession,
    ) -> Result<Option<SubscriptionStats>, ClassifiedError> {
        let request = web_request(
            self.routes.subscription.clone(),
            session,
            b"{}".to_vec(),
            &self.web_timezone,
        )?;
        match self.web_transport.send(&request, cancellation).await {
            Ok(response) if response.status() == 200 => {
                parse_subscription_response(response.body()).map(Some)
            }
            Err(TransportError::Cancelled) => Err(network_error()),
            Ok(_) | Err(_) => Ok(None),
        }
    }
}

impl Debug for KimiProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mode = match self.mode {
            KimiMode::Code { .. } => "code",
            KimiMode::Web { .. } => "web",
        };
        formatter
            .debug_struct("KimiProvider")
            .field("scope", &self.scope)
            .field("source", &self.source)
            .field("mode", &mode)
            .field("routes", &self.routes)
            .field("code_transport", &"<redacted>")
            .field("web_transport", &"<redacted>")
            .field("enrichment_session_count", &self.enrichment_sessions.len())
            .field("subscription_grace", &self.subscription_grace)
            .field("web_timezone", &"<redacted>")
            .finish()
    }
}

impl ProviderAdapter for KimiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Kimi)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct RequiredUsage {
    weekly: UsageDetail,
    rate_limit: Option<RateLimit>,
}

struct KimiSnapshot {
    weekly: UsageDetail,
    rate_limit: Option<RateLimit>,
    subscription: Option<SubscriptionStats>,
    fetched_at: Timestamp,
}

struct UsageDetail {
    limit: String,
    used: Option<String>,
    remaining: Option<String>,
    reset_time: Option<String>,
}

struct RateLimit {
    duration_minutes: Option<i64>,
    detail: UsageDetail,
}

struct SubscriptionStats {
    balance: Option<SubscriptionBalance>,
    code_weekly: Option<SubscriptionRateLimit>,
}

struct SubscriptionBalance {
    feature: Option<String>,
    kind: Option<String>,
    used_ratio: f64,
    expires_at: Option<String>,
}

struct SubscriptionRateLimit {
    ratio: f64,
    enabled: Option<bool>,
    reset_time: Option<String>,
}

fn parse_code_response(bytes: &[u8]) -> Result<KimiSnapshot, ClassifiedError> {
    let root = parse_bounded_json(bytes)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    let weekly = parse_usage_detail(object.get("usage").ok_or_else(parse_error)?)?;
    let rate_limit = parse_first_rate_limit(object.get("limits"))?;
    Ok(KimiSnapshot {
        weekly,
        rate_limit,
        subscription: None,
        fetched_at: Timestamp::from_unix_timestamp(0).map_err(|_| parse_error())?,
    })
}

fn parse_web_response(bytes: &[u8]) -> Result<RequiredUsage, ClassifiedError> {
    let root = parse_bounded_json(bytes)?;
    let usages = root
        .as_object()
        .and_then(|object| object.get("usages"))
        .and_then(Value::as_array)
        .ok_or_else(parse_error)?;
    let coding = usages
        .iter()
        .find_map(|value| {
            let object = value.as_object()?;
            (object.get("scope").and_then(Value::as_str) == Some("FEATURE_CODING"))
                .then_some(object)
        })
        .ok_or_else(parse_error)?;
    let weekly = parse_usage_detail(coding.get("detail").ok_or_else(parse_error)?)?;
    let rate_limit = parse_first_rate_limit(coding.get("limits"))?;
    Ok(RequiredUsage { weekly, rate_limit })
}

fn parse_first_rate_limit(value: Option<&Value>) -> Result<Option<RateLimit>, ClassifiedError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    let values = value.as_array().ok_or_else(parse_error)?;
    let Some(first) = values.first() else {
        return Ok(None);
    };
    let object = first.as_object().ok_or_else(parse_error)?;
    let window = object
        .get("window")
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;
    let duration = flexible_i64(window.get("duration"));
    let unit = window.get("timeUnit").and_then(Value::as_str);
    let duration_minutes = duration.and_then(|duration| window_minutes(duration, unit));
    let detail = parse_usage_detail(object.get("detail").ok_or_else(parse_error)?)?;
    Ok(Some(RateLimit {
        duration_minutes,
        detail,
    }))
}

fn parse_usage_detail(value: &Value) -> Result<UsageDetail, ClassifiedError> {
    let object = value.as_object().ok_or_else(parse_error)?;
    let limit = flexible_string(object.get("limit")).ok_or_else(parse_error)?;
    let used = flexible_string(object.get("used"));
    let remaining = flexible_string(object.get("remaining"));
    let reset_time = ["resetTime", "resetAt", "reset_time", "reset_at"]
        .into_iter()
        .find_map(|key| flexible_string(object.get(key)));
    Ok(UsageDetail {
        limit,
        used,
        remaining,
        reset_time,
    })
}

fn parse_subscription_response(bytes: &[u8]) -> Result<SubscriptionStats, ClassifiedError> {
    let root = parse_bounded_json(bytes)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    let balance = object
        .get("subscriptionBalance")
        .filter(|value| !value.is_null())
        .map(parse_subscription_balance)
        .transpose()?
        .flatten();
    let code_weekly = object
        .get("ratelimitCode7d")
        .filter(|value| !value.is_null())
        .map(parse_subscription_rate_limit)
        .transpose()?
        .flatten();
    Ok(SubscriptionStats {
        balance,
        code_weekly,
    })
}

fn parse_subscription_balance(
    value: &Value,
) -> Result<Option<SubscriptionBalance>, ClassifiedError> {
    let object = value.as_object().ok_or_else(parse_error)?;
    let Some(used_ratio) = flexible_f64(object.get("amountUsedRatio")) else {
        return Ok(None);
    };
    if !used_ratio.is_finite() {
        return Ok(None);
    }
    Ok(Some(SubscriptionBalance {
        feature: bounded_optional_string(object.get("feature"))?,
        kind: bounded_optional_string(object.get("type"))?,
        used_ratio,
        expires_at: bounded_optional_string(object.get("expireTime"))?,
    }))
}

fn parse_subscription_rate_limit(
    value: &Value,
) -> Result<Option<SubscriptionRateLimit>, ClassifiedError> {
    let object = value.as_object().ok_or_else(parse_error)?;
    let Some(ratio) = flexible_f64(object.get("ratio")) else {
        return Ok(None);
    };
    if !ratio.is_finite() {
        return Ok(None);
    }
    let enabled = match object.get("enabled") {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Null) | None => None,
        Some(_) => return Ok(None),
    };
    Ok(Some(SubscriptionRateLimit {
        ratio,
        enabled,
        reset_time: bounded_optional_string(object.get("resetTime"))?,
    }))
}

fn snapshot_to_sample(
    scope: AccountScope,
    fetched_at: Timestamp,
    snapshot: KimiSnapshot,
    strategy: &'static str,
) -> Result<UsageSample, ClassifiedError> {
    if snapshot.fetched_at != fetched_at {
        return Err(api_error());
    }
    let primary = usage_window(&snapshot.weekly, Some(WEEKLY_MINUTES), WindowKind::Weekly)?;
    let secondary = snapshot
        .rate_limit
        .as_ref()
        .map(|rate| usage_window(&rate.detail, rate.duration_minutes, WindowKind::Rate))
        .transpose()?
        .flatten();
    let mut extra = Vec::new();
    if let Some(subscription) = snapshot.subscription {
        if let Some(balance) = subscription.balance
            && (balance.feature.as_deref().is_none()
                || balance.feature.as_deref() == Some("FEATURE_OMNI"))
            && (balance.kind.as_deref().is_none()
                || balance.kind.as_deref() == Some("SUBSCRIPTION"))
        {
            let percent = percent_from_ratio(balance.used_ratio)?;
            let duration = WindowDuration::from_provider_minutes(MONTHLY_SENTINEL_MINUTES)
                .map_err(|_| parse_error())?;
            let resets_at = parse_optional_timestamp(balance.expires_at.as_deref());
            let window = RateWindow::new(
                WindowUsage::known(percent),
                Some(duration),
                resets_at,
                None,
                None,
                false,
            )
            .map_err(|_| parse_error())?;
            extra.push(named_window("kimi-monthly", "Total usage", window)?);
        }
        if let Some(code_weekly) = subscription.code_weekly
            && code_weekly.enabled != Some(false)
        {
            let percent = percent_from_ratio(code_weekly.ratio)?;
            let duration =
                WindowDuration::from_provider_minutes(WEEKLY_MINUTES).map_err(|_| parse_error())?;
            let resets_at = parse_optional_timestamp(code_weekly.reset_time.as_deref());
            let window = RateWindow::new(
                WindowUsage::known(percent),
                Some(duration),
                resets_at,
                None,
                None,
                false,
            )
            .map_err(|_| parse_error())?;
            if !weekly_windows_equivalent(&window, primary.as_ref()) {
                extra.push(named_window("kimi-code-7d", "Code 7-day", window)?);
            }
        }
    }
    let mut builder = UsageSampleBuilder::new(scope, fetched_at).extra_windows(extra);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("kimi", strategy)?.build()
}

#[derive(Clone, Copy)]
enum WindowKind {
    Weekly,
    Rate,
}

fn usage_window(
    detail: &UsageDetail,
    reliable_minutes: Option<i64>,
    kind: WindowKind,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let Ok(limit) = detail.limit.parse::<i64>() else {
        return Ok(None);
    };
    if limit <= 0 {
        return Ok(None);
    }
    let (used, reliable) = if let Some(used) = detail
        .used
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
    {
        (used, true)
    } else if let Some(remaining) = detail
        .remaining
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (0..=limit).contains(value))
    {
        (limit - remaining, true)
    } else {
        (0, false)
    };
    let percent = count_percent(used, limit)?;
    let duration = if reliable {
        reliable_minutes
            .map(WindowDuration::from_provider_minutes)
            .transpose()
            .map_err(|_| parse_error())?
    } else {
        None
    };
    let resets_at = parse_optional_timestamp(detail.reset_time.as_deref());
    let description = match kind {
        WindowKind::Weekly => format!("{used}/{limit} requests"),
        WindowKind::Rate => rate_description(used, limit, duration),
    };
    let description = BoundedText::new(description).map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(percent),
        duration,
        resets_at,
        Some(description),
        None,
        false,
    )
    .map(Some)
    .map_err(|_| parse_error())
}

fn rate_description(used: i64, limit: i64, duration: Option<WindowDuration>) -> String {
    let Some(duration) = duration else {
        return format!("Rate: {used}/{limit}");
    };
    let minutes = duration.seconds() / 60;
    if minutes.is_multiple_of(60) {
        let hours = minutes / 60;
        format!(
            "Rate: {used}/{limit} per {hours} {}",
            if hours == 1 { "hour" } else { "hours" }
        )
    } else {
        format!(
            "Rate: {used}/{limit} per {minutes} {}",
            if minutes == 1 { "minute" } else { "minutes" }
        )
    }
}

fn weekly_windows_equivalent(code: &RateWindow, weekly: Option<&RateWindow>) -> bool {
    let Some(weekly) = weekly else { return false };
    if weekly.duration().is_none() {
        return false;
    }
    let Some(code_percent) = code.used_percent() else {
        return false;
    };
    let Some(weekly_percent) = weekly.used_percent() else {
        return false;
    };
    if (code_percent.get() - weekly_percent.get()).abs() > 1.0 {
        return false;
    }
    let (Some(code_reset), Some(weekly_reset)) = (code.resets_at(), weekly.resets_at()) else {
        return false;
    };
    code_reset
        .unix_timestamp()
        .abs_diff(weekly_reset.unix_timestamp())
        <= 5 * 60
}

fn named_window(
    id: &'static str,
    title: &'static str,
    window: RateWindow,
) -> Result<NamedRateWindow, ClassifiedError> {
    let id = BoundedText::new(id).map_err(|_| api_error())?;
    let title = BoundedText::new(title).map_err(|_| api_error())?;
    Ok(NamedRateWindow::new(id, title, window))
}

fn percent_from_ratio(ratio: f64) -> Result<UsagePercent, ClassifiedError> {
    UsagePercent::new((ratio * 100.0).clamp(0.0, 100.0)).map_err(|_| parse_error())
}

fn window_minutes(duration: i64, unit: Option<&str>) -> Option<i64> {
    if duration <= 0 {
        return None;
    }
    let multiplier = match unit {
        Some("TIME_UNIT_MINUTE") => 1,
        Some("TIME_UNIT_HOUR") => 60,
        Some("TIME_UNIT_DAY") => 24 * 60,
        Some(_) | None => return None,
    };
    duration.checked_mul(multiplier)
}

fn parse_optional_timestamp(raw: Option<&str>) -> Option<Timestamp> {
    raw.and_then(|value| Timestamp::parse(value).ok())
}

fn parse_bounded_json(bytes: &[u8]) -> Result<Value, ClassifiedError> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| parse_error())?;
    validate_json_tree(&value)?;
    Ok(value)
}

fn validate_json_tree(root: &Value) -> Result<(), ClassifiedError> {
    let mut stack = vec![(root, 1_usize)];
    let mut nodes = 0_usize;
    let mut strings = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(parse_error)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(parse_error());
        }
        match value {
            Value::String(value) => add_json_string(&mut strings, value)?,
            Value::Array(values) => {
                for value in values {
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    add_json_string(&mut strings, key)?;
                    stack.push((value, depth + 1));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn add_json_string(total: &mut usize, value: &str) -> Result<(), ClassifiedError> {
    if value.len() > MAX_JSON_STRING_BYTES {
        return Err(parse_error());
    }
    *total = total
        .checked_add(value.len())
        .filter(|total| *total <= MAX_JSON_AGGREGATE_BYTES)
        .ok_or_else(parse_error)?;
    Ok(())
}

fn flexible_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Some(value.to_string())
            } else if let Some(value) = value.as_u64() {
                Some(value.to_string())
            } else {
                value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .map(|value| {
                        if value.fract() == 0.0 {
                            format!("{value:.0}")
                        } else {
                            value.to_string()
                        }
                    })
            }
        }
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

fn flexible_i64(value: Option<&Value>) -> Option<i64> {
    flexible_string(value)?.parse().ok()
}

fn flexible_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

fn bounded_optional_string(value: Option<&Value>) -> Result<Option<String>, ClassifiedError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    let value = value.as_str().ok_or_else(parse_error)?;
    if value.len() > MAX_JSON_STRING_BYTES {
        return Err(parse_error());
    }
    Ok(Some(value.to_owned()))
}

fn web_request(
    url: Url,
    session: &WebSession,
    body: Vec<u8>,
    timezone: &str,
) -> Result<HttpRequest, ClassifiedError> {
    let cookie = Zeroizing::new(format!("kimi-auth={}", session.token.as_str()));
    let authentication = Authentication::bearer_and_cookie(
        session.token.as_str().to_owned(),
        cookie.as_str().to_owned(),
    )
    .map_err(classify_transport)?;
    let mut request = HttpRequest::post_json(url, body)
        .map_err(classify_transport)?
        .authentication(authentication)
        .accept(RequestAccept::Any)
        .accepted_statuses(&[400, 401, 403])
        .map_err(classify_transport)?
        .public_header("origin", WEB_ORIGIN)
        .and_then(|request| request.public_header("referer", "https://www.kimi.com/code/console"))
        .and_then(|request| request.public_header("accept-language", "en-US,en;q=0.9"))
        .and_then(|request| request.public_header("user-agent", WEB_USER_AGENT))
        .and_then(|request| request.public_header("connect-protocol-version", "1"))
        .and_then(|request| request.public_header("x-language", "en-US"))
        .and_then(|request| request.public_header("x-msh-platform", "web"))
        .and_then(|request| request.public_header("r-timezone", timezone))
        .map_err(classify_transport)?;
    if let Some(info) = jwt_session_info(session.token.as_str()) {
        for (name, value) in info {
            request = request
                .sensitive_header(name, value)
                .map_err(classify_transport)?;
        }
    }
    Ok(request)
}

fn jwt_session_info(jwt: &str) -> Option<Vec<(&'static str, String)>> {
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() || payload.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    if bytes.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    validate_json_tree(&value).ok()?;
    let object = value.as_object()?;
    let mut headers = Vec::new();
    for (claim, header) in [
        ("device_id", "x-msh-device-id"),
        ("ssid", "x-msh-session-id"),
        ("sub", "x-traffic-id"),
    ] {
        if let Some(value) = object
            .get(claim)
            .and_then(Value::as_str)
            .and_then(safe_ascii_header)
        {
            headers.push((header, value));
        }
    }
    Some(headers)
}

fn parse_web_token(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    if raw.len() > 64 * 1024 || raw.contains('\0') {
        return Err(parse_error());
    }
    let cleaned =
        cleaned_secret(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if looks_like_jwt(cleaned) {
        validate_bare_web_token(cleaned)?;
        return Ok(Zeroizing::new(cleaned.to_owned()));
    }
    if let Some((name, value)) = cleaned.split_once(':')
        && name.trim().eq_ignore_ascii_case("kimi-auth")
    {
        let value = value.trim();
        validate_cookie_token(value)?;
        return Ok(Zeroizing::new(value.to_owned()));
    }
    let policy = ManualCapturePolicy::new(
        ["www.kimi.com", "kimi.com"],
        [CaptureHeader::Cookie, CaptureHeader::Authorization],
    )
    .map_err(classify_capture_error)?
    .with_ignored_url_query();
    let capture = policy.parse(cleaned).map_err(classify_capture_error)?;
    if let Some(cookie) = capture.header(CaptureHeader::Cookie) {
        return token_from_cookie(cookie);
    }
    if let Some(authorization) = capture.header(CaptureHeader::Authorization) {
        let token = authorization
            .get(..7)
            .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))
            .map(|_| authorization[7..].trim())
            .ok_or_else(parse_error)?;
        validate_cookie_token(token)?;
        return Ok(Zeroizing::new(token.to_owned()));
    }
    Err(ClassifiedError::new(ErrorKind::MissingCredential))
}

fn resolved_web_token(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let value =
        cleaned_secret(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    validate_cookie_token(value)?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn manual_environment_token(
    environment: &BTreeMap<String, String>,
) -> Result<Zeroizing<String>, ClassifiedError> {
    if let Some(raw) = environment
        .get("KIMI_MANUAL_COOKIE")
        .and_then(|value| clean_setting(value))
        && let Ok(token) = parse_web_token(raw)
    {
        return Ok(token);
    }
    if let Some(raw) = environment
        .get("KIMI_AUTH_TOKEN")
        .and_then(|value| clean_setting(value))
    {
        return parse_web_token(raw).or_else(|_| resolved_web_token(raw));
    }
    environment
        .get("kimi_auth_token")
        .and_then(|value| clean_setting(value))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
        .and_then(resolved_web_token)
}

fn token_from_cookie(cookie: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut selected = None;
    for pair in cookie.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            return Err(parse_error());
        };
        if name.trim().eq_ignore_ascii_case("kimi-auth") {
            if selected.is_some() {
                return Err(parse_error());
            }
            selected = Some(value.trim());
        }
    }
    let token = selected.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    validate_cookie_token(token)?;
    Ok(Zeroizing::new(token.to_owned()))
}

fn validate_bare_web_token(token: &str) -> Result<(), ClassifiedError> {
    validate_cookie_token(token)?;
    if !looks_like_jwt(token) {
        return Err(parse_error());
    }
    Ok(())
}

fn validate_cookie_token(token: &str) -> Result<(), ClassifiedError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'=' | b'/')
        })
    {
        return Err(parse_error());
    }
    Authentication::bearer(token.to_owned()).map_err(classify_transport)?;
    Ok(())
}

fn looks_like_jwt(value: &str) -> bool {
    value.starts_with("eyJ") && value.split('.').count() == 3
}

fn cleaned_secret(raw: &str) -> Option<&str> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = value[1..value.len() - 1].trim();
    }
    (!value.is_empty()).then_some(value)
}

fn browser_sessions(
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    _routes: &KimiRouteSet,
    now: OffsetDateTime,
) -> Result<Vec<WebSession>, ClassifiedError> {
    let allowlist = BrowserCookieDomainAllowlist::new([
        BrowserCookieDomainRule {
            domain: "www.kimi.com",
            policy: BrowserCookieDomainPolicy::Exact,
        },
        BrowserCookieDomainRule {
            domain: "kimi.com",
            policy: BrowserCookieDomainPolicy::Exact,
        },
    ])
    .map_err(|_| parse_error())?;
    let target = ValidatedCookieUrl::parse(
        "https://www.kimi.com/apiv2/kimi.gateway.billing.v1.BillingService/GetUsages",
        CookieUrlPolicy::HttpsOnly,
    )
    .map_err(|_| api_error())?;
    let report = discovery.discover();
    let mut sessions = Vec::new();
    let mut seen = HashSet::new();
    for (index, profile) in report.profiles().iter().enumerate() {
        if index >= MAX_BROWSER_PROFILES {
            return Err(parse_error());
        }
        let id = u16::try_from(index + 1).map_err(|_| parse_error())?;
        let source = CookieSourceId::new(id);
        let Ok(import) = import_browser_cookies_merging_chromium_stores_with_decryptor(
            profile, source, &allowlist, decryptor,
        ) else {
            continue;
        };
        let order = CookieImportOrder::new([source]).map_err(|_| parse_error())?;
        let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error())?;
        let Some(header) = jar.header_for(&target, now).map_err(|_| parse_error())? else {
            continue;
        };
        let Ok(token) = token_from_cookie(header.expose()) else {
            continue;
        };
        let digest = Sha256::digest(token.as_bytes());
        if seen.insert(digest.to_vec()) {
            sessions.push(WebSession { token });
            if sessions.len() > MAX_BROWSER_SESSIONS {
                return Err(parse_error());
            }
        }
    }
    if sessions.is_empty() {
        Err(ClassifiedError::new(ErrorKind::MissingCredential))
    } else {
        Ok(sessions)
    }
}

fn configured_code_base(
    environment: &BTreeMap<String, String>,
) -> Result<(Url, EndpointClass), ClassifiedError> {
    if let Some(raw) = environment
        .get(CODE_API_BASE_ENV)
        .and_then(|value| clean_setting(value))
    {
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::HttpsOnly)?;
        return Ok((endpoint.url().clone(), endpoint.class()));
    }
    let url = Url::parse(CODE_API_ORIGIN).map_err(|_| api_error())?;
    Ok((url, EndpointClass::PublicHttps))
}

fn code_usage_endpoint(base: &Url, class: EndpointClass) -> Result<Url, ClassifiedError> {
    if base.as_str().len() > 16 * 1024
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(api_error());
    }
    validate_request_url(base, class)?;
    let segments = base
        .path_segments()
        .ok_or_else(api_error)?
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let suffix: &[&str] = if segments.ends_with(&["coding", "v1"]) {
        &["usages"]
    } else if segments.ends_with(&["coding"]) {
        &["v1", "usages"]
    } else {
        &["coding", "v1", "usages"]
    };
    let mut url = base.clone();
    {
        let mut path = url.path_segments_mut().map_err(|()| api_error())?;
        path.pop_if_empty();
        for segment in suffix {
            path.push(segment);
        }
    }
    validate_request_url(&url, class)?;
    Ok(url)
}

fn validate_root_origin(origin: &Url, class: EndpointClass) -> Result<(), ClassifiedError> {
    if origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(api_error());
    }
    EndpointPolicy::new([(origin.as_str(), class)])
        .map_err(|_| api_error())?
        .validate(origin)
        .map_err(|_| api_error())?;
    Ok(())
}

fn validate_request_url(url: &Url, class: EndpointClass) -> Result<(), ClassifiedError> {
    let origin = url.origin().ascii_serialization();
    EndpointPolicy::new([(origin, class)])
        .map_err(|_| api_error())?
        .validate(url)
        .map_err(|_| api_error())?;
    Ok(())
}

fn with_fixed_path(origin: &Url, path: &str) -> Url {
    let mut url = origin.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn exact_transport(
    url: &Url,
    class: EndpointClass,
    timeout: Duration,
) -> Result<HttpTransport, ClassifiedError> {
    let policy = EndpointPolicy::new([(url.origin().ascii_serialization(), class)])
        .map_err(|_| api_error())?;
    policy.validate(url).map_err(|_| api_error())?;
    let config = TransportConfig::new(
        CONNECT_TIMEOUT,
        timeout,
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(classify_transport)?;
    HttpTransport::new(policy, config).map_err(classify_transport)
}

fn validate_provider_scope(
    scope: &AccountScope,
    source: ProviderSource,
) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Kimi
        || !descriptor_for(ProviderId::Kimi).sources().contains(source)
    {
        return Err(api_error());
    }
    Ok(())
}

fn credential_bearer(credential: &KimiCredential) -> Result<Authentication, ClassifiedError> {
    credential.authentication()
}

fn classify_code_status(status: u16) -> Result<(), ClassifiedError> {
    match status {
        200 => Ok(()),
        401 => Err(auth_error()),
        403 => Err(ClassifiedError::new(ErrorKind::PermissionDenied)),
        _ => Err(api_error()),
    }
}

fn classify_web_status(status: u16) -> Result<(), ClassifiedError> {
    match status {
        200 => Ok(()),
        401 | 403 => Err(auth_error()),
        _ => Err(api_error()),
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used directly as a map_err callback throughout the adapter"
)]
fn classify_transport(error: TransportError) -> ClassifiedError {
    error.classified()
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    ClassifiedError::new(match error {
        ManualCaptureError::MissingSecret => ErrorKind::MissingCredential,
        ManualCaptureError::InvalidPolicy
        | ManualCaptureError::InputTooLarge
        | ManualCaptureError::InvalidSyntax
        | ManualCaptureError::UnsafeSyntax
        | ManualCaptureError::UnsafeOption
        | ManualCaptureError::TooManyTokens
        | ManualCaptureError::TooManyHeaders
        | ManualCaptureError::InvalidSecret
        | ManualCaptureError::DuplicateSecret
        | ManualCaptureError::ConflictingHeader
        | ManualCaptureError::DisallowedHeader
        | ManualCaptureError::DisallowedUrl => ErrorKind::Parse,
    })
}

fn source_strategy(source: ProviderSource) -> &'static str {
    match source {
        ProviderSource::ApiKey => "api_key",
        ProviderSource::Cli => "cli_oauth",
        ProviderSource::ManualCookie => "manual_cookie",
        ProviderSource::BrowserSession => "browser_session",
        ProviderSource::LocalData => "desktop_cookie",
        ProviderSource::ConfigurableEndpoint
        | ProviderSource::OAuth
        | ProviderSource::CloudCredentials => "configured",
    }
}

fn has_cli_endpoint_override(environment: &BTreeMap<String, String>) -> bool {
    environment
        .get(CODE_API_BASE_ENV)
        .and_then(|value| clean_setting(value))
        .is_some()
        || OAUTH_HOST_ENVS.iter().any(|key| {
            environment
                .get(*key)
                .and_then(|value| clean_setting(value))
                .is_some()
        })
}

fn code_home(environment: &BTreeMap<String, String>) -> Result<PathBuf, ClassifiedError> {
    let home = if let Some(value) = environment
        .get(CODE_HOME_ENV)
        .and_then(|value| clean_setting(value))
    {
        PathBuf::from(value)
    } else {
        let home = environment
            .get("HOME")
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        PathBuf::from(home).join(".kimi-code")
    };
    validate_path(&home)?;
    Ok(home)
}

fn validate_path(path: &Path) -> Result<(), ClassifiedError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(api_error());
    }
    Ok(())
}

fn read_bounded_file(
    path: &Path,
    max_u64: u64,
    max_usize: usize,
) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    validate_path(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options.open(path).map_err(|error| classify_io(&error))?;
    read_open_file(file, max_u64, max_usize)
}

fn read_open_file(
    mut file: File,
    max_u64: u64,
    max_usize: usize,
) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    let metadata = file.metadata().map_err(|error| classify_io(&error))?;
    if !metadata.file_type().is_file() || metadata.len() > max_u64 {
        return Err(parse_error());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(max_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| classify_io(&error))?;
    if bytes.len() > max_usize {
        return Err(parse_error());
    }
    Ok(bytes)
}

fn classify_io(error: &std::io::Error) -> ClassifiedError {
    match error.kind() {
        IoErrorKind::NotFound => ClassifiedError::new(ErrorKind::MissingCredential),
        IoErrorKind::PermissionDenied => ClassifiedError::new(ErrorKind::PermissionDenied),
        _ => parse_error(),
    }
}

fn fallback_device_id(home: &Path, device_name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(home.as_os_str().as_bytes());
    digest.update([0]);
    digest.update(device_name.as_bytes());
    let bytes = digest.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn safe_ascii_header(raw: &str) -> Option<String> {
    if raw.len() > 8 * 1024 {
        return None;
    }
    let value = raw
        .chars()
        .filter(|character| character.is_ascii() && !character.is_ascii_control())
        .collect::<String>();
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn local_web_timezone() -> String {
    std::env::var("TZ")
        .ok()
        .and_then(|value| validated_timezone(value.trim_start_matches(':')))
        .or_else(|| {
            fs::read_link("/etc/localtime")
                .ok()
                .and_then(|path| timezone_from_zoneinfo_path(&path))
        })
        .unwrap_or_else(|| "UTC".to_owned())
}

fn timezone_from_zoneinfo_path(path: &Path) -> Option<String> {
    let path = path.to_str()?;
    let (_, timezone) = path.rsplit_once("/zoneinfo/")?;
    validated_timezone(timezone)
}

fn validated_timezone(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty()
        || value.len() > MAX_TIMEZONE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+'))
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return None;
    }
    Some(value.to_owned())
}

fn desktop_database_version(connection: &rusqlite::Connection) -> Result<u32, ClassifiedError> {
    let exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='meta')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| parse_error())?;
    if exists == 0 {
        return Ok(0);
    }
    let value = connection.query_row(
        "SELECT value FROM meta WHERE key='version' LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    );
    match value {
        Ok(value) => value.parse().map_err(|_| parse_error()),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(_) => Err(parse_error()),
    }
}

fn desktop_decrypted_value(
    host: &str,
    database_version: u32,
    mut value: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>, ClassifiedError> {
    if database_version >= 24 {
        if value.len() < 32 {
            return Err(parse_error());
        }
        let expected = Sha256::digest(host.as_bytes());
        if value[..32] != expected[..] {
            return Err(parse_error());
        }
        value.drain(..32);
    }
    let string = String::from_utf8(std::mem::take(&mut *value)).map_err(|_| parse_error())?;
    Ok(Zeroizing::new(string))
}

fn sqlite_text(value: ValueRef<'_>) -> Result<String, ClassifiedError> {
    let bytes = match value {
        ValueRef::Text(bytes) => bytes,
        ValueRef::Null => return Ok(String::new()),
        ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Blob(_) => return Err(parse_error()),
    };
    if bytes.len() > MAX_DESKTOP_FIELD_BYTES {
        return Err(parse_error());
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| parse_error())
}

fn sqlite_blob(value: ValueRef<'_>) -> Result<Vec<u8>, ClassifiedError> {
    let bytes = match value {
        ValueRef::Blob(bytes) => bytes,
        ValueRef::Null | ValueRef::Text([]) => return Ok(Vec::new()),
        ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Text(_) => return Err(parse_error()),
    };
    if bytes.len() > MAX_DESKTOP_FIELD_BYTES {
        return Err(parse_error());
    }
    Ok(bytes.to_vec())
}

#[derive(Deserialize)]
struct KimiCliDocument {
    #[serde(default)]
    access_token: OwnedSecret,
    #[serde(rename = "refresh_token", default)]
    _refresh_token: Option<OwnedSecret>,
    #[serde(default, deserialize_with = "deserialize_optional_f64")]
    expires_at: Option<f64>,
}

struct OwnedSecret(Zeroizing<String>);

impl Default for OwnedSecret {
    fn default() -> Self {
        Self(Zeroizing::new(String::new()))
    }
}

impl<'de> Deserialize<'de> for OwnedSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .map(Zeroizing::new)
            .map(Self)
    }
}

fn deserialize_optional_f64<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(Value::Number(value)) => value.as_f64(),
        Some(Value::String(value)) => value.parse().ok(),
        Some(Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_)) | None => None,
    })
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn auth_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::AuthenticationExpired)
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn network_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Network)
}
