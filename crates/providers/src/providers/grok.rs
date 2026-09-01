//! Grok Build billing adapter over the CLI's bounded JSON-RPC stdio surface.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsageSample,
    WindowDuration, WindowUsage,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroizing;

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptor, import_browser_cookies_merging_chromium_stores_with_decryptor,
};
use crate::browser_profile::BrowserProfileDiscovery;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieHeaderNormalizer, CookieImport, CookieImportOrder, CookieJar, CookieSourceId,
    CookieUrlPolicy, ValidatedCookieUrl,
};
use crate::descriptor::ProviderSource;
use crate::endpoint::classify_https_endpoint;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::executable::ExecutablePath;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::json_rpc_child::{JsonRpcChildError, JsonRpcChildRequest, JsonRpcVersion};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, count_percent, system_timestamp};
use crate::provider_files::ProviderFileRoot;
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
    TransportError,
};

const MAX_RPC_FRAME_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_AUTH_FILE_BYTES: usize = 64 * 1024;
const MAX_PROXY_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SETTINGS_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SETTINGS_TIER_BYTES: usize = 256;
const MAX_BROWSER_PROFILES: usize = 256;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_WEB_RESPONSE_BYTES: usize = 1024 * 1024;
const BILLING_PROXY_ORIGIN: &str = "https://cli-chat-proxy.grok.com/";
const BILLING_PROXY_URL: &str = "https://cli-chat-proxy.grok.com/v1/billing?format=credits";
const SETTINGS_PROXY_URL: &str = "https://cli-chat-proxy.grok.com/v1/settings";
const WEB_BILLING_ORIGIN: &str = "https://grok.com/";
const WEB_BILLING_URL: &str = "https://grok.com/grok_api_v2.GrokBuildBilling/GetGrokCreditsConfig";
const MANUAL_COOKIE_ENVIRONMENT: &str = "OMARCHY_AI_BAR_GROK_COOKIE";
const SETTINGS_BUDGET: Duration = Duration::from_secs(2);
const WEB_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CHILD_ENVIRONMENT_ALLOWLIST: [&str; 13] = [
    "HOME",
    "PATH",
    "GROK_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
];

/// Closed Grok source planner matching the pinned `CodexBar` settings choices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GrokSourceMode {
    /// Try CLI, then the read-only OAuth billing proxy, then configured web cookies.
    #[default]
    Auto,
    /// Use only the Grok CLI JSON-RPC surface.
    Cli,
    /// Use only the read-only `SuperGrok` OAuth billing proxy.
    OAuth,
    /// Use only a manual or browser grok.com session.
    Web,
}

/// Closed browser-cookie preference for Grok web billing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GrokCookieSource {
    /// Permit lazy browser-profile discovery after authentication failures.
    #[default]
    Auto,
    /// Use the named application-owned manual cookie slot.
    Manual,
    /// Never use grok.com cookies.
    Off,
}

/// Already-resolved Grok executable and bounded child environment.
pub struct GrokSettings {
    executable: Option<ExecutablePath>,
    environment: BTreeMap<String, String>,
    grok_home: Option<PathBuf>,
    source_mode: GrokSourceMode,
    cookie_source: GrokCookieSource,
}

impl GrokSettings {
    #[must_use]
    pub fn new(executable: Option<ExecutablePath>, environment: BTreeMap<String, String>) -> Self {
        let configured_home = environment
            .get("GROK_HOME")
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let user_home = environment
            .get("HOME")
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let grok_home = configured_home.map_or_else(
            || user_home.as_ref().map(|home| home.join(".grok")),
            |configured| {
                if configured.is_absolute() {
                    Some(configured)
                } else if let (Some(home), Ok(relative)) =
                    (user_home.as_ref(), configured.strip_prefix("~"))
                {
                    Some(home.join(relative))
                } else {
                    user_home.as_ref().map(|home| home.join(configured))
                }
            },
        );
        Self {
            executable,
            environment,
            grok_home,
            source_mode: GrokSourceMode::Auto,
            cookie_source: GrokCookieSource::Auto,
        }
    }

    /// Selects one exact source plan without reading credentials.
    #[must_use]
    pub const fn with_source_mode(mut self, source_mode: GrokSourceMode) -> Self {
        self.source_mode = source_mode;
        self
    }

    /// Selects the web-cookie policy without reading browser state.
    #[must_use]
    pub const fn with_cookie_source(mut self, cookie_source: GrokCookieSource) -> Self {
        self.cookie_source = cookie_source;
        self
    }
}

impl std::fmt::Debug for GrokSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrokSettings")
            .field("has_executable", &self.executable.is_some())
            .field("environment", &"<redacted>")
            .field("grok_home", &self.grok_home.as_ref().map(|_| "<redacted>"))
            .field("source_mode", &self.source_mode)
            .field("cookie_source", &self.cookie_source)
            .finish()
    }
}

/// One exact Grok Build account discovered and queried through its CLI.
pub struct GrokProvider {
    scope: AccountScope,
    settings: GrokSettings,
}

impl GrokProvider {
    /// Binds the Grok CLI to one exact account scope.
    ///
    /// # Errors
    ///
    /// Returns an API classification when the scope is not Grok.
    pub fn new(scope: AccountScope, settings: GrokSettings) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Grok {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { scope, settings })
    }

    async fn fetch_billing(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        match self.settings.source_mode {
            GrokSourceMode::Cli => self.fetch_cli_billing(context).await,
            GrokSourceMode::OAuth => self.fetch_proxy_billing(context).await,
            GrokSourceMode::Web => self.fetch_manual_web_billing(context).await,
            GrokSourceMode::Auto => {
                match self.fetch_cli_billing(context).await {
                    Ok(sample) => return Ok(sample),
                    // Pinned CodexBar advances from its CLI strategy on every
                    // non-cancellation failure in Auto mode. Keep that broad
                    // local-to-OAuth transition distinct from cookie fallback:
                    // it does not read browser state or mutate either source.
                    Err(_error) if should_advance_cli_to_oauth(context) => {}
                    Err(error) => return Err(error),
                }
                let proxy_error = match self.fetch_proxy_billing(context).await {
                    Ok(sample) => return Ok(sample),
                    Err(error) if should_advance_to_cookie(&error) => error,
                    Err(error) => return Err(error),
                };
                if self.settings.cookie_source == GrokCookieSource::Manual {
                    return self
                        .fetch_manual_web_billing(context)
                        .await
                        .map_err(|web_error| resolve_source_error(proxy_error, web_error));
                }
                // OAuth is the immediately preceding strategy, so its result
                // alone controls the outer authentication-only browser gate.
                // A CLI parse/outage must not mask a missing OAuth credential
                // and strand an otherwise valid browser session.
                Err(proxy_error)
            }
        }
    }

    async fn fetch_cli_billing(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        let Some(executable) = self.settings.executable.as_ref() else {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        };
        let mut request = JsonRpcChildRequest::new(
            executable.clone(),
            ["agent", "stdio"],
            JsonRpcVersion::V2,
            MAX_RPC_FRAME_BYTES,
            MAX_STDERR_BYTES,
        )
        .map_err(|error| classify_rpc(&error))?
        .with_cleared_environment();
        for name in CHILD_ENVIRONMENT_ALLOWLIST {
            if let Some(value) = self.settings.environment.get(name) {
                request = request
                    .with_environment(name, value)
                    .map_err(|error| classify_rpc(&error))?;
            }
        }
        let mut child = request
            .spawn(context.cancellation())
            .await
            .map_err(|error| classify_rpc(&error))?;
        let initialized = child
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": "1",
                    "clientCapabilities": {
                        "fs": {"readTextFile": false, "writeTextFile": false},
                        "terminal": false
                    }
                })),
                Duration::from_secs(4),
                context.cancellation(),
            )
            .await;
        if let Err(error) = initialized {
            child.shutdown().await;
            return Err(classify_rpc(&error));
        }
        let result = child
            .request(
                "x.ai/billing",
                Some(json!({})),
                Duration::from_secs(3),
                context.cancellation(),
            )
            .await;
        child.shutdown().await;
        match result {
            Ok(value) => serde_json::from_value(value)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
                .and_then(|billing| {
                    normalize_billing(self.scope.clone(), system_timestamp()?, billing)
                }),
            Err(error) => Err(classify_rpc(&error)),
        }
    }

    async fn fetch_manual_web_billing(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        if self.settings.cookie_source != GrokCookieSource::Manual {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let raw = self
            .settings
            .environment
            .get(MANUAL_COOKIE_ENVIRONMENT)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let session = GrokWebSession::from_manual_capture(raw)?;
        fetch_web_session(&self.scope, ProviderSource::ManualCookie, &session, context).await
    }

    async fn fetch_proxy_billing(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        let credentials = self.load_credentials(context)?;
        let endpoint =
            Url::parse(BILLING_PROXY_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let origin =
            Url::parse(BILLING_PROXY_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let endpoint_class =
            classify_https_endpoint(&origin).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let source = self.proxy_source();
        let client = FixedApiClient::new_bearer(
            self.scope.clone(),
            endpoint.clone(),
            endpoint_class,
            credentials.token.clone(),
            proxy_transport_config()?,
        )?
        .with_source(source)?;
        let response = client
            .get_json_with_public_headers_and_status_map(
                context,
                endpoint,
                &[("x-xai-token-auth", "xai-grok-cli")],
                |status| (status == 403).then_some(ErrorKind::AuthenticationExpired),
            )
            .await?;
        let billing: ProxyBilling = response.json()?;
        let billing = normalize_proxy_billing_usage(billing)?;
        let fetched_at = system_timestamp()?;
        // The settings request enriches an already-successful billing fetch.
        // It uses the same captured bearer, has its own hard two-second
        // budget, and is deliberately unable to turn valid usage into an
        // error (including when refresh cancellation arrives during it).
        let settings_tier = self.fetch_settings_tier(context, &credentials).await;
        build_proxy_billing_sample(
            self.scope.clone(),
            fetched_at,
            billing,
            credentials,
            settings_tier,
        )
    }

    async fn fetch_settings_tier(
        &self,
        context: &ProviderContext,
        credentials: &GrokCredentials,
    ) -> Option<String> {
        let lookup = async {
            let endpoint =
                Url::parse(SETTINGS_PROXY_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            let origin = Url::parse(BILLING_PROXY_ORIGIN)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            let endpoint_class = classify_https_endpoint(&origin)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            let client = FixedApiClient::new_bearer(
                self.scope.clone(),
                endpoint.clone(),
                endpoint_class,
                credentials.token.clone(),
                settings_transport_config()?,
            )?
            .with_source(self.proxy_source())?;
            let response = client
                .get_json_with_public_headers(
                    context,
                    endpoint,
                    &[("x-xai-token-auth", "xai-grok-cli")],
                )
                .await?;
            Ok(parse_settings_tier(response.body()))
        };
        best_effort_settings_tier(SETTINGS_BUDGET, lookup).await
    }

    const fn proxy_source(&self) -> ProviderSource {
        match self.settings.source_mode {
            GrokSourceMode::OAuth => ProviderSource::OAuth,
            GrokSourceMode::Web => ProviderSource::ManualCookie,
            GrokSourceMode::Auto | GrokSourceMode::Cli => ProviderSource::Cli,
        }
    }

    fn load_credentials(
        &self,
        context: &ProviderContext,
    ) -> Result<GrokCredentials, ClassifiedError> {
        if let Some(token) = ["OMARCHY_AI_BAR_GROK_OAUTH_TOKEN", "GROK_OAUTH_TOKEN"]
            .into_iter()
            .filter_map(|key| self.settings.environment.get(key))
            .find_map(|value| normalize_oauth_token(value))
        {
            return Ok(GrokCredentials {
                token: ApiKeyCredential::from_zeroizing(Zeroizing::new(token))?,
                email: None,
                team_id: None,
                auth_mode: Some("oidc".to_owned()),
                principal_type: None,
            });
        }
        let home = self
            .settings
            .grok_home
            .as_ref()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let root = ProviderFileRoot::open(home)
            .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let contents = root
            .read("auth.json", MAX_AUTH_FILE_BYTES, context.cancellation())
            .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
        parse_credentials(contents.as_bytes())
    }
}

impl ProviderAdapter for GrokProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Grok)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move { self.fetch_billing(context).await })
    }
}

/// One exact Grok account backed by lazily discovered Linux browser sessions.
pub struct GrokBrowserProvider {
    scope: AccountScope,
    sessions: Vec<GrokWebSession>,
}

impl GrokBrowserProvider {
    /// Imports isolated grok.com sessions from already-validated browser profiles.
    ///
    /// # Errors
    ///
    /// Returns stable bounded discovery, cookie, or account-scope errors.
    pub fn new(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Grok {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let sessions = grok_browser_sessions(discovery, decryptor, now)?;
        Ok(Self { scope, sessions })
    }

    async fn fetch_browser_billing(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::BrowserSession {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let mut last_auth_error = None;
        for session in &self.sessions {
            match fetch_web_session(
                &self.scope,
                ProviderSource::BrowserSession,
                session,
                context,
            )
            .await
            {
                Ok(sample) => return Ok(sample),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::AuthenticationExpired | ErrorKind::PermissionDenied
                    ) =>
                {
                    last_auth_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_auth_error.unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }
}

impl ProviderAdapter for GrokBrowserProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Grok)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move { self.fetch_browser_billing(context).await })
    }
}

struct GrokWebSession {
    cookie: Zeroizing<String>,
}

impl GrokWebSession {
    fn from_manual_capture(raw: &str) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(["grok.com"], [CaptureHeader::Cookie])
            .map_err(classify_manual_cookie_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_manual_cookie_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        validated_grok_cookie(cookie, OffsetDateTime::now_utc())
    }
}

fn grok_browser_sessions(
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: OffsetDateTime,
) -> Result<Vec<GrokWebSession>, ClassifiedError> {
    let allowlist = BrowserCookieDomainAllowlist::new([BrowserCookieDomainRule {
        domain: "grok.com",
        policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
    }])
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let target = grok_web_cookie_target()?;
    let report = discovery.discover();
    if report.profiles().len() > MAX_BROWSER_PROFILES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut sessions = Vec::new();
    let mut seen = HashSet::<[u8; 32]>::new();
    for (index, profile) in report.profiles().iter().enumerate() {
        let source_number =
            u16::try_from(index + 1).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let source = CookieSourceId::new(source_number);
        let Ok(import) = import_browser_cookies_merging_chromium_stores_with_decryptor(
            profile, source, &allowlist, decryptor,
        ) else {
            continue;
        };
        let order =
            CookieImportOrder::new([source]).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let jar = CookieJar::from_imports(&order, [import])
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let Some(header) = jar
            .header_for(&target, now)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        else {
            continue;
        };
        if !has_required_grok_cookie(header.expose())? {
            continue;
        }
        let digest: [u8; 32] = Sha256::digest(header.expose().as_bytes()).into();
        if seen.insert(digest) {
            sessions.push(GrokWebSession {
                cookie: Zeroizing::new(header.expose().to_owned()),
            });
            if sessions.len() > MAX_BROWSER_SESSIONS {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
        }
    }
    if sessions.is_empty() {
        return Err(ClassifiedError::new(if report.is_empty() {
            ErrorKind::MissingCredential
        } else {
            ErrorKind::AuthenticationExpired
        }));
    }
    Ok(sessions)
}

fn validated_grok_cookie(
    raw: &str,
    now: OffsetDateTime,
) -> Result<GrokWebSession, ClassifiedError> {
    if !has_required_grok_cookie(raw)? {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let target = grok_web_cookie_target()?;
    let import = CookieImport::from_host_only_capture(CookieSourceId::MANUAL, raw, &target, None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let order = CookieImportOrder::new([CookieSourceId::MANUAL])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let jar = CookieJar::from_imports(&order, [import])
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let header = jar
        .header_for(&target, now)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    Ok(GrokWebSession {
        cookie: Zeroizing::new(header.expose().to_owned()),
    })
}

fn has_required_grok_cookie(raw: &str) -> Result<bool, ClassifiedError> {
    CookieHeaderNormalizer::filtered(Some(raw), &["sso", "sso-rw"])
        .map(|header| header.is_some())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn grok_web_cookie_target() -> Result<ValidatedCookieUrl, ClassifiedError> {
    ValidatedCookieUrl::parse(WEB_BILLING_URL, CookieUrlPolicy::HttpsOnly)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn classify_manual_cookie_error(error: ManualCaptureError) -> ClassifiedError {
    ClassifiedError::new(match error {
        ManualCaptureError::MissingSecret => ErrorKind::MissingCredential,
        _ => ErrorKind::Parse,
    })
}

async fn fetch_web_session(
    scope: &AccountScope,
    source: ProviderSource,
    session: &GrokWebSession,
    context: &ProviderContext,
) -> Result<UsageSample, ClassifiedError> {
    let origin =
        Url::parse(WEB_BILLING_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let endpoint = Url::parse(WEB_BILLING_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let policy = EndpointPolicy::new([(origin.as_str(), EndpointClass::PublicHttps)])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let transport =
        HttpTransport::new(policy, web_transport_config()?).map_err(|error| error.classified())?;
    let authentication = Authentication::cookie(session.cookie.as_str().to_owned())
        .map_err(|error| error.classified())?;
    let request = HttpRequest::post(endpoint, vec![0, 0, 0, 0, 0])
        .map_err(|error| error.classified())?
        .authentication(authentication)
        .accept(RequestAccept::Any)
        .content_type(RequestContentType::GrpcWebProto)
        .public_header("origin", "https://grok.com")
        .map_err(|error| error.classified())?
        .public_header("referer", "https://grok.com/?_s=usage")
        .map_err(|error| error.classified())?
        .public_header("x-grpc-web", "1")
        .map_err(|error| error.classified())?
        .public_header("x-user-agent", "connect-es/2.1.1")
        .map_err(|error| error.classified())?
        .response_headers(&["grpc-status", "grpc-message"])
        .map_err(|error| error.classified())?;

    for attempt in 0..=1 {
        let response = match transport.send(&request, context.cancellation()).await {
            Ok(response) => response,
            Err(error) if attempt == 0 && should_retry_web_transport(&error) => continue,
            Err(error) => return Err(error.classified()),
        };
        let fetched_at = system_timestamp()?;
        match parse_web_billing_response(&response, fetched_at) {
            Ok(primary) => {
                return UsageSampleBuilder::new(scope.clone(), fetched_at)
                    .primary(primary)
                    .provenance(
                        "grok",
                        match source {
                            ProviderSource::ManualCookie => "manual_cookie",
                            ProviderSource::BrowserSession => "browser_session",
                            _ => return Err(ClassifiedError::new(ErrorKind::Api)),
                        },
                    )?
                    .build();
            }
            Err(failure) if attempt == 0 && failure.retryable => {}
            Err(failure) => return Err(failure.error),
        }
    }
    Err(ClassifiedError::new(ErrorKind::Network))
}

fn should_retry_web_transport(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Timeout
            | TransportError::Network
            | TransportError::RequestTimeout
            | TransportError::ProviderUnavailable {
                status: 502..=504,
                ..
            }
    )
}

struct WebResponseFailure {
    error: ClassifiedError,
    retryable: bool,
}

fn parse_web_billing_response(
    response: &crate::transport::HttpResponse,
    now: Timestamp,
) -> Result<RateWindow, WebResponseFailure> {
    if let Some(status) = response.header("grpc-status") {
        validate_grpc_status(status, response.header("grpc-message").unwrap_or_default())?;
    }
    validate_grpc_trailers(response.body())?;
    parse_grpc_web_billing(response.body(), now).map_err(|error| WebResponseFailure {
        error,
        retryable: false,
    })
}

fn validate_grpc_trailers(bytes: &[u8]) -> Result<(), WebResponseFailure> {
    let Some(frames) = grpc_web_frames(bytes) else {
        return Ok(());
    };
    for frame in frames.into_iter().filter(|frame| frame.flags & 0x80 != 0) {
        let text = std::str::from_utf8(frame.payload).map_err(|_| WebResponseFailure {
            error: ClassifiedError::new(ErrorKind::Parse),
            retryable: false,
        })?;
        let mut status = None;
        let mut message = "";
        for line in text.lines().take(64) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("grpc-status") {
                status = Some(value.trim());
            } else if name.trim().eq_ignore_ascii_case("grpc-message") {
                message = value.trim();
            }
        }
        if let Some(status) = status {
            validate_grpc_status(status, message)?;
        }
    }
    Ok(())
}

fn validate_grpc_status(status: &str, message: &str) -> Result<(), WebResponseFailure> {
    let status = status
        .trim()
        .parse::<u16>()
        .map_err(|_| WebResponseFailure {
            error: ClassifiedError::new(ErrorKind::Parse),
            retryable: false,
        })?;
    if status == 0 {
        return Ok(());
    }
    let message = percent_decode_ascii(message);
    let lower = message.to_ascii_lowercase();
    let retryable = status == 4
        || (status == 1
            && ["timeout", "deadline", "expired"]
                .iter()
                .any(|needle| lower.contains(needle)));
    let kind = if retryable {
        ErrorKind::Network
    } else if status == 8 {
        ErrorKind::RateLimited
    } else if matches!(status, 13 | 14) {
        ErrorKind::ProviderUnavailable
    } else if status == 16
        || (status == 7
            && (lower.contains("bad-credentials")
                || lower.contains("unauthenticated")
                || (lower.contains("oauth2") && lower.contains("could not be validated"))
                || (lower.contains("access token")
                    && ["invalid", "expired", "could not be validated"]
                        .iter()
                        .any(|needle| lower.contains(needle)))))
    {
        ErrorKind::AuthenticationExpired
    } else if status == 7 {
        ErrorKind::PermissionDenied
    } else {
        ErrorKind::Api
    };
    Err(WebResponseFailure {
        error: ClassifiedError::new(kind),
        retryable,
    })
}

fn percent_decode_ascii(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut output = Vec::with_capacity(bytes.len().min(8 * 1024));
    let mut index = 0;
    while index < bytes.len() && output.len() < 8 * 1024 {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
        {
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

struct GrpcWebFrame<'a> {
    flags: u8,
    payload: &'a [u8],
}

fn grpc_web_frames(bytes: &[u8]) -> Option<Vec<GrpcWebFrame<'_>>> {
    let mut frames = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        let header = bytes.get(index..index.checked_add(5)?)?;
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let start = index.checked_add(5)?;
        let end = start.checked_add(length)?;
        let payload = bytes.get(start..end)?;
        frames.push(GrpcWebFrame {
            flags: header[0],
            payload,
        });
        index = end;
    }
    Some(frames)
}

#[derive(Default)]
struct ProtobufScan {
    fixed32: Vec<Fixed32Field>,
    varints: Vec<VarintField>,
}

struct Fixed32Field {
    path: Vec<u64>,
    value: f32,
    order: usize,
}

struct VarintField {
    path: Vec<u64>,
    value: u64,
}

fn parse_grpc_web_billing(bytes: &[u8], now: Timestamp) -> Result<RateWindow, ClassifiedError> {
    let framed = grpc_web_frames(bytes);
    let payloads = framed
        .as_ref()
        .map(|frames| {
            frames
                .iter()
                .filter(|frame| frame.flags & 0x80 == 0)
                .map(|frame| frame.payload)
                .collect::<Vec<_>>()
        })
        .filter(|payloads| !payloads.is_empty())
        .or_else(|| looks_like_protobuf(bytes).then(|| vec![bytes]))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut scan = ProtobufScan::default();
    let mut order = 0_usize;
    for payload in payloads {
        scan_protobuf(payload, 0, &[], &mut order, &mut scan);
    }
    let percent = scan
        .fixed32
        .iter()
        .filter(|field| {
            field.path.last() == Some(&1)
                && field.value.is_finite()
                && (0.0..=100.0).contains(&field.value)
        })
        .min_by_key(|field| (field.path.len(), field.order))
        .map(|field| f64::from(field.value));
    let now_seconds = now.unix_timestamp();
    let mut resets = scan
        .varints
        .iter()
        .filter_map(|field| {
            let seconds = i64::try_from(field.value).ok()?;
            ((1_700_000_000..=2_100_000_000).contains(&seconds) && seconds > now_seconds)
                .then_some((field.path.as_slice(), seconds))
        })
        .collect::<Vec<_>>();
    resets.sort_by_key(|(path, seconds)| (*path != [1, 5, 1], *seconds));
    let reset = resets
        .first()
        .and_then(|(_, seconds)| Timestamp::from_unix_timestamp(*seconds).ok());
    let has_usage_period = scan.varints.iter().any(|field| {
        field.path.starts_with(&[1, 6])
            || (field.path.as_slice() == [1, 8, 1] && matches!(field.value, 1 | 2))
    });
    let no_usage_yet =
        percent.is_none() && scan.fixed32.is_empty() && reset.is_some() && has_usage_period;
    let percent = percent
        .or(no_usage_yet.then_some(0.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let usage = WindowUsage::known(
        oab_domain::UsagePercent::new(percent)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    );
    RateWindow::new(usage, None, reset, None, None, false)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn looks_like_protobuf(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|first| {
        let field = first >> 3;
        let wire = first & 0x07;
        field > 0 && matches!(wire, 0 | 1 | 2 | 5)
    })
}

fn scan_protobuf(
    bytes: &[u8],
    depth: usize,
    path: &[u64],
    order: &mut usize,
    scan: &mut ProtobufScan,
) {
    let mut index = 0_usize;
    while index < bytes.len() {
        let field_start = index;
        let Some(key) = read_varint(bytes, &mut index).filter(|key| *key != 0) else {
            index = field_start.saturating_add(1);
            continue;
        };
        let mut field_path = path.to_vec();
        field_path.push(key >> 3);
        match key & 0x07 {
            0 => {
                if let Some(value) = read_varint(bytes, &mut index) {
                    scan.varints.push(VarintField {
                        path: field_path,
                        value,
                    });
                } else {
                    index = field_start.saturating_add(1);
                }
            }
            1 => {
                let Some(end) = index.checked_add(8).filter(|end| *end <= bytes.len()) else {
                    break;
                };
                index = end;
            }
            2 => {
                let Some(length) =
                    read_varint(bytes, &mut index).and_then(|value| usize::try_from(value).ok())
                else {
                    index = field_start.saturating_add(1);
                    continue;
                };
                let Some(end) = index.checked_add(length).filter(|end| *end <= bytes.len()) else {
                    index = field_start.saturating_add(1);
                    continue;
                };
                if depth < 4 {
                    scan_protobuf(&bytes[index..end], depth + 1, &field_path, order, scan);
                }
                index = end;
            }
            5 => {
                let Some(raw) = bytes.get(index..index.saturating_add(4)) else {
                    break;
                };
                scan.fixed32.push(Fixed32Field {
                    path: field_path,
                    value: f32::from_bits(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
                    order: *order,
                });
                *order = order.saturating_add(1);
                index = index.saturating_add(4);
            }
            _ => index = field_start.saturating_add(1),
        }
    }
}

fn read_varint(bytes: &[u8], index: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    while *index < bytes.len() && shift < 64 {
        let byte = bytes[*index];
        *index += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn classify_rpc(error: &JsonRpcChildError) -> ClassifiedError {
    let kind = match error {
        JsonRpcChildError::Spawn => ErrorKind::MissingCredential,
        JsonRpcChildError::Cancelled
        | JsonRpcChildError::Timeout
        | JsonRpcChildError::StdinClosed
        | JsonRpcChildError::StdoutRead
        | JsonRpcChildError::StderrRead
        | JsonRpcChildError::Closed => ErrorKind::Network,
        JsonRpcChildError::StdoutTooLarge
        | JsonRpcChildError::StderrTooLarge
        | JsonRpcChildError::Protocol => ErrorKind::Parse,
        JsonRpcChildError::Remote(error) => classify_rpc_remote(error.expose_message()),
        JsonRpcChildError::InvalidConfiguration => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn classify_rpc_remote(message: &str) -> ErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("rate limit") || lower.contains("too many requests") {
        ErrorKind::RateLimited
    } else if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("network")
        || lower.contains("connection")
    {
        ErrorKind::Network
    } else if lower.contains("unavailable")
        || lower.contains("internal server")
        || lower.contains("server error")
    {
        ErrorKind::ProviderUnavailable
    } else if lower.contains("unauthorized")
        || lower.contains("unauthenticated")
        || lower.contains("authentication")
        || lower.contains("sign in")
        || lower.contains("login")
        || (lower.contains("token") && lower.contains("expired"))
        || lower.contains("credential")
    {
        ErrorKind::AuthenticationExpired
    } else {
        ErrorKind::Api
    }
}

fn should_advance_cli_to_oauth(context: &ProviderContext) -> bool {
    !context.cancellation().is_cancelled()
}

const fn should_advance_to_cookie(error: &ClassifiedError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::MissingCredential | ErrorKind::AuthenticationExpired
    )
}

fn resolve_source_error(
    earlier_error: ClassifiedError,
    later_error: ClassifiedError,
) -> ClassifiedError {
    if later_error.kind() == ErrorKind::MissingCredential {
        earlier_error
    } else {
        later_error
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrokBilling {
    billing_cycle: Option<GrokBillingCycle>,
    monthly_limit: Option<GrokCent>,
    usage: Option<GrokUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrokBillingCycle {
    billing_period_start: Option<String>,
    billing_period_end: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrokUsage {
    total_used: Option<GrokCent>,
}

#[derive(Debug, Deserialize)]
struct GrokCent {
    val: Option<i64>,
}

#[derive(Debug)]
struct GrokCredentials {
    token: ApiKeyCredential,
    email: Option<String>,
    team_id: Option<String>,
    auth_mode: Option<String>,
    principal_type: Option<String>,
}

#[derive(Deserialize)]
struct GrokCredentialEntry {
    key: Option<String>,
    email: Option<String>,
    team_id: Option<String>,
    auth_mode: Option<String>,
    principal_type: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyBilling {
    config: Option<ProxyBillingConfig>,
    subscription_tier: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyBillingConfig {
    credit_usage_percent: Option<f64>,
    current_period: Option<ProxyCurrentPeriod>,
    billing_period_end: Option<String>,
    on_demand_cap: Option<ProxyAmount>,
    on_demand_used: Option<ProxyAmount>,
    subscription_tier: Option<String>,
}

#[derive(Deserialize)]
struct ProxyCurrentPeriod {
    end: Option<String>,
}

#[derive(Deserialize)]
struct ProxyAmount {
    val: Option<f64>,
}

#[derive(Deserialize)]
struct ProxySettings {
    subscription_tier_display: Option<String>,
}

struct NormalizedProxyBilling {
    primary: RateWindow,
    subscription_tier: Option<String>,
}

fn normalize_billing(
    scope: AccountScope,
    fetched_at: Timestamp,
    billing: GrokBilling,
) -> Result<UsageSample, ClassifiedError> {
    let limit = billing
        .monthly_limit
        .and_then(|value| value.val)
        .filter(|value| *value > 0)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let used = billing
        .usage
        .and_then(|usage| usage.total_used)
        .and_then(|value| value.val)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let (duration, reset) = billing.billing_cycle.map_or(Ok((None, None)), |cycle| {
        let start = cycle
            .billing_period_start
            .as_deref()
            .map(Timestamp::parse)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let end = cycle
            .billing_period_end
            .as_deref()
            .map(Timestamp::parse)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let duration = match (start, end) {
            (Some(start), Some(end)) if end > start => {
                let seconds = end.unix_timestamp() - start.unix_timestamp();
                Some(
                    WindowDuration::from_seconds(
                        u64::try_from(seconds)
                            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                    )
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                )
            }
            _ => None,
        };
        Ok((duration, end))
    })?;
    let primary = RateWindow::new(
        WindowUsage::known(count_percent(used, limit)?),
        duration,
        reset,
        None,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .login_method(Some("Grok Build".to_owned()))?
        .provenance("grok", "cli")?
        .build()
}

fn parse_credentials(bytes: &[u8]) -> Result<GrokCredentials, ClassifiedError> {
    parse_credentials_at(bytes, system_timestamp()?)
}

fn parse_credentials_at(bytes: &[u8], now: Timestamp) -> Result<GrokCredentials, ClassifiedError> {
    let mut root: BTreeMap<String, GrokCredentialEntry> =
        serde_json::from_slice(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let preferred = root
        .iter()
        .find(|(scope, entry)| scope.starts_with("https://auth.x.ai::") && entry_has_token(entry))
        .map(|(scope, _)| scope)
        .cloned()
        .or_else(|| {
            root.iter()
                .find(|(scope, entry)| scope.contains("/sign-in") && entry_has_token(entry))
                .map(|(scope, _)| scope)
                .cloned()
        })
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let mut entry = root
        .remove(&preferred)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if entry
        .expires_at
        .as_deref()
        .and_then(|value| Timestamp::parse(value).ok())
        .is_some_and(|expiry| now >= expiry)
    {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let token = entry
        .key
        .take()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    Ok(GrokCredentials {
        token: ApiKeyCredential::from_zeroizing(Zeroizing::new(token))?,
        email: entry.email.filter(|value| !value.trim().is_empty()),
        team_id: entry.team_id.filter(|value| !value.trim().is_empty()),
        auth_mode: entry.auth_mode.filter(|value| !value.trim().is_empty()),
        principal_type: entry
            .principal_type
            .filter(|value| !value.trim().is_empty()),
    })
}

fn entry_has_token(entry: &GrokCredentialEntry) -> bool {
    entry
        .key
        .as_deref()
        .map(str::trim)
        .is_some_and(|token| !token.is_empty())
}

fn normalize_oauth_token(value: &str) -> Option<String> {
    let mut token = value.trim();
    if token
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
    {
        token = token.get(7..)?.trim();
    }
    let lower = token.to_ascii_lowercase();
    if token.is_empty()
        || lower.starts_with("cookie:")
        || lower.starts_with("xai-")
        || token.contains('=')
    {
        return None;
    }
    Some(token.to_owned())
}

fn normalize_proxy_billing_usage(
    billing: ProxyBilling,
) -> Result<NormalizedProxyBilling, ClassifiedError> {
    let config = billing
        .config
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let percent = config
        .credit_usage_percent
        .filter(|value| value.is_finite())
        .or_else(|| {
            let cap = config.on_demand_cap?.val?;
            let used = config.on_demand_used?.val?;
            (cap.is_finite() && used.is_finite() && cap > 0.0).then_some(used / cap * 100.0)
        })
        .map(|value| value.clamp(0.0, 100.0));
    let resets_at = config
        .current_period
        .and_then(|period| period.end)
        .or(config.billing_period_end)
        .map(|value| Timestamp::parse(&value))
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if percent.is_none() && resets_at.is_none() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let usage = match percent {
        Some(percent) => WindowUsage::known(
            oab_domain::UsagePercent::new(percent)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None => WindowUsage::unknown(),
    };
    let primary = RateWindow::new(usage, None, resets_at, None, None, false)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let subscription_tier = config
        .subscription_tier
        .or(billing.subscription_tier)
        .and_then(|value| grok_plan_display(&value));
    Ok(NormalizedProxyBilling {
        primary,
        subscription_tier,
    })
}

fn build_proxy_billing_sample(
    scope: AccountScope,
    fetched_at: Timestamp,
    billing: NormalizedProxyBilling,
    credentials: GrokCredentials,
    settings_tier: Option<String>,
) -> Result<UsageSample, ClassifiedError> {
    let plan = settings_tier.or(billing.subscription_tier);
    let login_method = plan.or_else(|| {
        credentials.auth_mode.map(|mode| {
            if mode.eq_ignore_ascii_case("oidc") {
                "SuperGrok".to_owned()
            } else {
                mode
            }
        })
    });
    let organization = credentials.team_id.or_else(|| {
        credentials
            .principal_type
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("team"))
            .then(|| "Team".to_owned())
    });
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(billing.primary)
        .email(credentials.email)?
        .organization(organization)?
        .login_method(login_method)?
        .provenance("grok", "cli_proxy")?
        .build()
}

fn parse_settings_tier(bytes: &[u8]) -> Option<String> {
    let settings: ProxySettings = serde_json::from_slice(bytes).ok()?;
    let tier = settings.subscription_tier_display?;
    let tier = tier.trim();
    if tier.is_empty() || tier.len() > MAX_SETTINGS_TIER_BYTES || tier.chars().any(char::is_control)
    {
        return None;
    }
    grok_plan_display(tier)
}

async fn best_effort_settings_tier<F>(budget: Duration, lookup: F) -> Option<String>
where
    F: Future<Output = Result<Option<String>, ClassifiedError>>,
{
    match tokio::time::timeout(budget, lookup).await {
        Ok(Ok(tier)) => tier,
        Ok(Err(_)) | Err(_) => None,
    }
}

fn grok_plan_display(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let compact = trimmed
        .to_ascii_lowercase()
        .chars()
        .filter(char::is_ascii_alphabetic)
        .collect::<String>();
    match compact.as_str() {
        "supergrokheavy" | "heavy" => Some("SuperGrok Heavy".to_owned()),
        "supergrok" => Some("SuperGrok".to_owned()),
        _ => Some(trimmed.to_owned()),
    }
}

fn proxy_transport_config() -> Result<TransportConfig, ClassifiedError> {
    let timeout = Duration::from_secs(15);
    TransportConfig::new(
        Duration::from_secs(5),
        timeout,
        MAX_PROXY_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), timeout),
    )
    .map_err(|error| error.classified())
}

fn settings_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        SETTINGS_BUDGET,
        SETTINGS_BUDGET,
        MAX_SETTINGS_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn web_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        WEB_REQUEST_TIMEOUT,
        MAX_WEB_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oab_domain::{AccountKey, ProviderInstanceId};
    use rusqlite::{Connection, params};

    use super::*;

    fn scope() -> AccountScope {
        AccountScope::new(
            ProviderId::Grok,
            ProviderInstanceId::new("default").unwrap(),
            AccountKey::new("ambient").unwrap(),
        )
    }

    #[test]
    fn normalizes_grok_billing() {
        let billing: GrokBilling = serde_json::from_value(json!({
            "billingCycle": {
                "billingPeriodStart": "2026-08-01T00:00:00Z",
                "billingPeriodEnd": "2026-09-01T00:00:00Z"
            },
            "monthlyLimit": {"val": 10000},
            "usage": {"totalUsed": {"val": 2500}}
        }))
        .unwrap();
        let sample = normalize_billing(
            scope(),
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            billing,
        )
        .unwrap();
        let percent = sample.primary().unwrap().used_percent().unwrap().get();
        assert!((percent - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn auth_file_prefers_a_usable_oidc_entry_and_falls_back_from_partial_oidc() {
        let now = Timestamp::parse("2026-08-30T10:00:00Z").unwrap();
        let oidc = parse_credentials_at(
            br#"{
              "https://accounts.x.ai/sign-in":{"key":"legacy","auth_mode":"session"},
              "https://auth.x.ai::client":{"key":"oidc","auth_mode":"oidc",
                "email":"grok@example.com","principal_type":"Team",
                "expires_at":"2026-09-01T00:00:00.123456789Z"}
            }"#,
            now,
        )
        .expect("usable OIDC entry");
        assert_eq!(oidc.auth_mode.as_deref(), Some("oidc"));
        assert_eq!(oidc.email.as_deref(), Some("grok@example.com"));
        assert_eq!(oidc.principal_type.as_deref(), Some("Team"));

        let legacy = parse_credentials_at(
            br#"{
              "https://auth.x.ai::client":{"auth_mode":"oidc"},
              "https://accounts.x.ai/sign-in":{"key":"legacy","auth_mode":"session"}
            }"#,
            now,
        )
        .expect("healthy legacy entry");
        assert_eq!(legacy.auth_mode.as_deref(), Some("session"));
    }

    #[test]
    fn expired_auth_file_is_classified_without_touching_owner_credentials() {
        let error = parse_credentials_at(
            br#"{"https://auth.x.ai::client":{"key":"stale","expires_at":"2020-01-01T00:00:00Z"}}"#,
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
        )
        .expect_err("expired Grok auth");
        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    }

    #[test]
    fn explicit_grok_oauth_token_normalization_matches_codexbar_routing() {
        assert_eq!(
            normalize_oauth_token("  Bearer abc.def.ghi  ").as_deref(),
            Some("abc.def.ghi")
        );
        assert!(normalize_oauth_token("Cookie: sso=abc").is_none());
        assert!(normalize_oauth_token("sso=abc; sso-rw=def").is_none());
        assert!(normalize_oauth_token("xai-management-key").is_none());
        assert!(normalize_oauth_token("   ").is_none());
    }

    #[test]
    fn auto_cli_to_oauth_matches_pinned_broad_fallback_but_cookie_fallback_is_auth_only() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let context = ProviderContext::new(scope(), ProviderSource::Cli, cancellation.clone());
        assert!(should_advance_cli_to_oauth(&context));
        cancellation.cancel();
        assert!(!should_advance_cli_to_oauth(&context));

        assert!(should_advance_to_cookie(&ClassifiedError::new(
            ErrorKind::MissingCredential
        )));
        assert!(should_advance_to_cookie(&ClassifiedError::new(
            ErrorKind::AuthenticationExpired
        )));
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::RateLimited,
            ErrorKind::ProviderUnavailable,
            ErrorKind::Network,
            ErrorKind::Parse,
            ErrorKind::Api,
        ] {
            assert!(!should_advance_to_cookie(&ClassifiedError::new(kind)));
        }

        let permission = ClassifiedError::new(ErrorKind::PermissionDenied);
        let preferred =
            resolve_source_error(ClassifiedError::new(ErrorKind::Network), permission.clone());
        assert_eq!(preferred, permission);

        let cli = ClassifiedError::new(ErrorKind::Parse);
        let preferred = resolve_source_error(
            cli.clone(),
            ClassifiedError::new(ErrorKind::MissingCredential),
        );
        assert_eq!(preferred, cli);

        assert_eq!(
            classify_rpc_remote("please sign in again"),
            ErrorKind::AuthenticationExpired
        );
        assert_eq!(
            classify_rpc_remote("rate limit exceeded"),
            ErrorKind::RateLimited
        );
        assert_eq!(
            classify_rpc_remote("service unavailable"),
            ErrorKind::ProviderUnavailable
        );
        assert_eq!(classify_rpc_remote("connection reset"), ErrorKind::Network);
    }

    #[test]
    fn manual_cookie_requires_the_grok_session_cookie_and_rejects_header_injection() {
        let session = GrokWebSession::from_manual_capture(
            "Cookie: analytics=public; sso=top-secret; sso-rw=second-secret",
        )
        .expect("bounded Grok cookie");
        assert!(!session.cookie.is_empty());
        assert!(GrokWebSession::from_manual_capture("analytics=value").is_err());
        assert!(GrokWebSession::from_manual_capture("Cookie: sso=value\nInjected: yes").is_err());
    }

    #[test]
    fn linux_firefox_profile_produces_one_isolated_grok_browser_session() {
        let fixture = tempfile::tempdir().expect("browser fixture");
        let home = fixture.path().join("home");
        let config = fixture.path().join("config");
        let root = home.join(".mozilla/firefox");
        let profile = root.join("fixture.default");
        fs::create_dir_all(&profile).expect("Firefox profile");
        fs::create_dir_all(&config).expect("config root");
        fs::write(
            root.join("profiles.ini"),
            "[Profile0]\nName=fixture\nIsRelative=1\nPath=fixture.default\nDefault=1\n",
        )
        .expect("Firefox profiles.ini");
        let connection = Connection::open(profile.join("cookies.sqlite")).expect("cookie database");
        connection
            .execute_batch(
                "CREATE TABLE moz_cookies(
                    host TEXT NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    expiry INTEGER NOT NULL,
                    isSecure INTEGER NOT NULL,
                    value TEXT NOT NULL
                 );",
            )
            .expect("Firefox cookie schema");
        for (name, value) in [("sso", "session-secret"), ("analytics", "retained")] {
            connection
                .execute(
                    "INSERT INTO moz_cookies(host, name, path, expiry, isSecure, value)
                     VALUES ('.grok.com', ?1, '/', 2000000000, 1, ?2)",
                    params![name, value],
                )
                .expect("Firefox Grok cookie");
        }
        drop(connection);
        let roots = crate::browser_profile::BrowserProfileRoots::new(
            &home,
            &config,
            None::<&std::path::Path>,
        )
        .expect("browser roots");
        let discovery = BrowserProfileDiscovery::with_roots(roots);

        let sessions = grok_browser_sessions(
            &discovery,
            &crate::browser_cookie::DisabledChromiumCookieDecryptor,
            OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixture time"),
        )
        .expect("Firefox Grok session");

        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].cookie.contains("sso="));
        assert!(sessions[0].cookie.contains("analytics="));
    }

    #[test]
    fn parses_pinned_grok_grpc_web_usage_frame() {
        let reset = 1_800_000_000_u64;
        let mut nested = vec![0x0d];
        nested.extend_from_slice(&42.5_f32.to_bits().to_le_bytes());
        nested.push(0x28);
        nested.extend(varint(reset));
        let mut payload = vec![0x0a, u8::try_from(nested.len()).unwrap()];
        payload.extend(nested);
        let mut frame = vec![0, 0, 0, 0, u8::try_from(payload.len()).unwrap()];
        frame.extend(payload);

        let window = parse_grpc_web_billing(
            &frame,
            Timestamp::from_unix_timestamp(1_799_000_000).unwrap(),
        )
        .expect("pinned Grok billing frame");
        assert_eq!(
            window.used_percent().map(oab_domain::UsagePercent::get),
            Some(42.5)
        );
        assert_eq!(
            window.resets_at().map(Timestamp::unix_timestamp),
            Some(i64::try_from(reset).unwrap())
        );
    }

    #[test]
    fn grpc_status_classification_does_not_trigger_browser_fallback_for_outages() {
        let auth =
            validate_grpc_status("16", "No credentials presented").expect_err("auth rejection");
        assert_eq!(auth.error.kind(), ErrorKind::AuthenticationExpired);
        assert!(!auth.retryable);

        let unavailable =
            validate_grpc_status("14", "service unavailable").expect_err("server rejection");
        assert_eq!(unavailable.error.kind(), ErrorKind::ProviderUnavailable);
        assert!(!unavailable.retryable);

        let deadline =
            validate_grpc_status("4", "deadline exceeded").expect_err("retryable deadline");
        assert_eq!(deadline.error.kind(), ErrorKind::Network);
        assert!(deadline.retryable);
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut encoded = Vec::new();
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap();
            value >>= 7;
            encoded.push(if value == 0 { byte } else { byte | 0x80 });
            if value == 0 {
                return encoded;
            }
        }
    }

    #[test]
    fn proxy_period_without_percent_keeps_unknown_usage_and_identity() {
        let billing: ProxyBilling = serde_json::from_value(json!({
            "config": {
                "currentPeriod": {"end":"2026-09-07T00:00:00Z"},
                "subscriptionTier":"SUPERGROK"
            }
        }))
        .expect("proxy billing");
        let credentials = GrokCredentials {
            token: ApiKeyCredential::new("opaque-token").unwrap(),
            email: Some("grok@example.com".to_owned()),
            team_id: Some("team-123".to_owned()),
            auth_mode: Some("oidc".to_owned()),
            principal_type: Some("Team".to_owned()),
        };
        let billing = normalize_proxy_billing_usage(billing).expect("normalized proxy billing");
        let sample = build_proxy_billing_sample(
            scope(),
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            billing,
            credentials,
            Some("SuperGrok Heavy".to_owned()),
        )
        .expect("period-only proxy payload");

        assert!(sample.primary().unwrap().used_percent().is_none());
        assert_eq!(
            sample
                .identity()
                .login_method()
                .map(oab_domain::BoundedText::as_str),
            Some("SuperGrok Heavy")
        );
        assert_eq!(
            sample
                .identity()
                .email()
                .map(oab_domain::BoundedText::as_str),
            Some("grok@example.com")
        );
    }

    #[test]
    fn settings_tier_parses_only_the_bounded_display_field_and_normalizes_plans() {
        assert_eq!(
            parse_settings_tier(
                br#"{"subscription_tier_display":" Heavy ","credential":"ignored"}"#,
            )
            .as_deref(),
            Some("SuperGrok Heavy")
        );
        assert_eq!(
            parse_settings_tier(br#"{"subscription_tier_display":"super_grok"}"#).as_deref(),
            Some("SuperGrok")
        );
    }

    #[test]
    fn missing_settings_enrichment_preserves_fetched_billing_usage() {
        let billing: ProxyBilling = serde_json::from_value(json!({
            "config": {"creditUsagePercent": 2.0}
        }))
        .expect("proxy billing");
        let billing = normalize_proxy_billing_usage(billing).expect("normalized proxy billing");
        let credentials = GrokCredentials {
            token: ApiKeyCredential::new("opaque-token").unwrap(),
            email: None,
            team_id: None,
            auth_mode: Some("oidc".to_owned()),
            principal_type: None,
        };

        let sample = build_proxy_billing_sample(
            scope(),
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            billing,
            credentials,
            None,
        )
        .expect("billing remains authoritative without settings");

        let percent = sample.primary().unwrap().used_percent().unwrap().get();
        assert!((percent - 2.0).abs() < f64::EPSILON);
        assert_eq!(
            sample
                .identity()
                .login_method()
                .map(oab_domain::BoundedText::as_str),
            Some("SuperGrok")
        );
    }

    #[test]
    fn missing_malformed_or_unbounded_settings_tier_is_ignored() {
        assert!(parse_settings_tier(br#"{"other":"value"}"#).is_none());
        assert!(parse_settings_tier(br#"{"subscription_tier_display":null}"#).is_none());
        assert!(parse_settings_tier(b"not-json").is_none());

        let oversized = format!(
            r#"{{"subscription_tier_display":"{}"}}"#,
            "x".repeat(MAX_SETTINGS_TIER_BYTES + 1)
        );
        assert!(parse_settings_tier(oversized.as_bytes()).is_none());
    }

    #[tokio::test]
    async fn settings_error_and_cancellation_are_best_effort() {
        let error = best_effort_settings_tier(Duration::from_secs(1), async {
            Err::<Option<String>, _>(ClassifiedError::new(ErrorKind::Network))
        })
        .await;
        assert!(error.is_none());

        let cancellation = tokio_util::sync::CancellationToken::new();
        let lookup_cancellation = cancellation.clone();
        cancellation.cancel();
        let cancelled = best_effort_settings_tier(Duration::from_secs(1), async move {
            lookup_cancellation.cancelled().await;
            Err::<Option<String>, _>(ClassifiedError::new(ErrorKind::Network))
        })
        .await;
        assert!(cancelled.is_none());
    }

    #[tokio::test]
    async fn settings_lookup_has_an_exact_two_second_production_budget() {
        assert_eq!(SETTINGS_BUDGET, Duration::from_secs(2));
        let timed_out = best_effort_settings_tier(Duration::from_millis(1), async {
            std::future::pending::<Result<Option<String>, ClassifiedError>>().await
        })
        .await;
        assert!(timed_out.is_none());
    }
}
