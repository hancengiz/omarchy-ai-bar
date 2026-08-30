//! `StepFun` rolling-window and token-plan credit usage.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use reqwest::header::{
    CONTENT_TYPE, COOKIE, HeaderMap, HeaderValue, LOCATION, SET_COOKIE,
    USER_AGENT as USER_AGENT_HEADER,
};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp, timestamp_from_unix};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, TransportConfig, TransportError,
};

const PRODUCTION_ORIGIN: &str = "https://platform.stepfun.com";
const USAGE_PATH: &str = "/api/step.openapi.devcenter.Dashboard/QueryStepPlanRateLimit";
const PLAN_STATUS_PATH: &str = "/api/step.openapi.devcenter.Dashboard/GetStepPlanStatus";
const REGISTER_DEVICE_PATH: &str = "/passport/proto.api.passport.v1.PassportService/RegisterDevice";
const SIGN_IN_PATH: &str = "/passport/proto.api.passport.v1.PassportService/SignInByPassword";
const REFRESH_PATH: &str = "/passport/proto.api.passport.v1.PassportService/RefreshToken";
const DEFAULT_WEB_ID: &str = "c8a1002d2c457e758785a9979832217c7c0b884c";
const APP_ID: &str = "10300";
const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_JSON_KEY_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_LOGIN_FIELD_BYTES: usize = 16 * 1024;
const MAX_SET_COOKIE_HEADERS: usize = 32;
const MAX_SET_COOKIE_BYTES: usize = 64 * 1024;
const MAX_REDIRECT_LOCATION_BYTES: usize = 8 * 1024;
const MAX_HOMEPAGE_REDIRECTS: u8 = 5;
const MAX_IDENTITY_BYTES: usize = 256;
const FIVE_HOUR_MINUTES: i64 = 5 * 60;
const WEEKLY_MINUTES: i64 = 7 * 24 * 60;
const MONTHLY_MINUTES: i64 = 30 * 24 * 60;

/// Fixed `StepFun` route table. Production routes cannot be redirected to a
/// caller-controlled host; loopback injection exists only for deterministic tests.
#[derive(Clone)]
pub struct StepFunRouteSet {
    homepage: Url,
    usage: Url,
    plan_status: Url,
    register_device: Url,
    sign_in: Url,
    refresh: Url,
    class: EndpointClass,
}

impl StepFunRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        let origin = Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?;
        Self::from_origin(origin, EndpointClass::PublicHttps)
    }

    /// Creates fixed routes below one loopback origin.
    ///
    /// # Errors
    ///
    /// Returns an API error when the origin is not a valid loopback authority.
    #[doc(hidden)]
    pub fn loopback(origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origin(origin, EndpointClass::LoopbackDevelopment)
    }

    fn from_origin(origin: Url, class: EndpointClass) -> Result<Self, ClassifiedError> {
        let routes = Self {
            homepage: fixed_url(origin.clone(), "/")?,
            usage: fixed_url(origin.clone(), USAGE_PATH)?,
            plan_status: fixed_url(origin.clone(), PLAN_STATUS_PATH)?,
            register_device: fixed_url(origin.clone(), REGISTER_DEVICE_PATH)?,
            sign_in: fixed_url(origin.clone(), SIGN_IN_PATH)?,
            refresh: fixed_url(origin, REFRESH_PATH)?,
            class,
        };
        routes.validate()?;
        Ok(routes)
    }

    fn validate(&self) -> Result<(), ClassifiedError> {
        if !matches!(
            self.class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) || self.homepage.path() != "/"
            || self.usage.path() != USAGE_PATH
            || self.plan_status.path() != PLAN_STATUS_PATH
            || self.register_device.path() != REGISTER_DEVICE_PATH
            || self.sign_in.path() != SIGN_IN_PATH
            || self.refresh.path() != REFRESH_PATH
            || [
                &self.homepage,
                &self.usage,
                &self.plan_status,
                &self.register_device,
                &self.sign_in,
                &self.refresh,
            ]
            .into_iter()
            .any(|url| {
                !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
            })
        {
            return Err(api_error());
        }
        if self.class == EndpointClass::PublicHttps {
            let expected = Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?;
            if [
                &self.homepage,
                &self.usage,
                &self.plan_status,
                &self.register_device,
                &self.sign_in,
                &self.refresh,
            ]
            .into_iter()
            .any(|url| url.origin() != expected.origin())
            {
                return Err(api_error());
            }
        }
        let policy = self.endpoint_policy()?;
        for endpoint in [
            &self.homepage,
            &self.usage,
            &self.plan_status,
            &self.register_device,
            &self.sign_in,
            &self.refresh,
        ] {
            policy.validate(endpoint).map_err(|_| api_error())?;
        }
        Ok(())
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new([(self.usage.origin().ascii_serialization(), self.class)])
            .map_err(|_| api_error())
    }
}

impl Debug for StepFunRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepFunRouteSet")
            .field("homepage", &"<redacted>")
            .field("usage", &"<redacted>")
            .field("plan_status", &"<redacted>")
            .field("register_device", &"<redacted>")
            .field("sign_in", &"<redacted>")
            .field("refresh", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

/// `StepFun` adapter bound to one manual Oasis token.
///
/// A successful refresh is retained in memory for subsequent daemon polls.
pub struct StepFunProvider {
    scope: AccountScope,
    routes: StepFunRouteSet,
    token: RwLock<Zeroizing<String>>,
    transport: HttpTransport,
    login: Option<StepFunLoginState>,
}

impl StepFunProvider {
    /// Creates the production adapter from a bare Oasis token, Cookie header,
    /// or copied cURL command.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, scope, or endpoint error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, StepFunRouteSet::production()?)
    }

    /// Creates an adapter with an injected route table.
    ///
    /// # Errors
    ///
    /// Returns the same stable failures as [`Self::new_manual`].
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: StepFunRouteSet,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::StepFun {
            return Err(api_error());
        }
        routes.validate()?;
        let token = token_from_manual_input(raw)?;
        validate_token(token.as_str())?;
        let transport = HttpTransport::new(routes.endpoint_policy()?, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            routes,
            token: RwLock::new(token),
            transport,
            login: None,
        })
    }

    /// Performs `StepFun`'s device-registration and password sign-in flow, then
    /// returns an adapter backed by the resulting in-memory Oasis token.
    ///
    /// The password is retained only in zeroizing memory so a later expired
    /// refresh token can perform the same authenticated recovery as the pinned
    /// provider. It is never logged or persisted by this adapter.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, endpoint, network, authentication,
    /// API, or parse error.
    pub async fn new_password(
        scope: AccountScope,
        username: &str,
        password: &str,
        cancellation: &CancellationToken,
    ) -> Result<Self, ClassifiedError> {
        Self::from_password_routes(
            scope,
            username,
            password,
            StepFunRouteSet::production()?,
            cancellation,
        )
        .await
    }

    /// Performs password sign-in against an injected fixed loopback route set.
    ///
    /// # Errors
    ///
    /// Returns the same stable failures as [`Self::new_password`].
    #[doc(hidden)]
    pub async fn from_password_routes(
        scope: AccountScope,
        username: &str,
        password: &str,
        routes: StepFunRouteSet,
        cancellation: &CancellationToken,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::StepFun {
            return Err(api_error());
        }
        routes.validate()?;
        let credentials = PasswordCredentials::new(username, password)?;
        let login_transport = StepFunLoginTransport::new(routes.endpoint_policy()?)?;
        let token = login_transport
            .login(&routes, &credentials, cancellation)
            .await?;
        let transport = HttpTransport::new(routes.endpoint_policy()?, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            routes,
            token: RwLock::new(token),
            transport,
            login: Some(StepFunLoginState {
                credentials,
                transport: login_transport,
            }),
        })
    }

    /// Fetches usage, refreshes an expired token once, and best-effort enriches
    /// the result with the active plan name.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, API, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let initial_token = self.token_copy().await;
        let (parsed, final_token) = match self.query_usage(initial_token.as_str(), context).await {
            Ok(parsed) => (parsed, initial_token),
            Err(error) if error.kind() == ErrorKind::AuthenticationExpired => {
                self.recover_usage(initial_token.as_str(), context).await?
            }
            Err(error) => return Err(error),
        };
        if context.cancellation().is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        let plan_name = self
            .query_plan_name(final_token.as_str(), context)
            .await
            .ok()
            .flatten();
        if context.cancellation().is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        normalize_usage(
            context.scope().clone(),
            fetched_at,
            &parsed,
            plan_name.as_deref(),
            self.strategy(),
        )
    }

    async fn recover_usage(
        &self,
        stale_token: &str,
        context: &ProviderContext,
    ) -> Result<(ParsedUsage, Zeroizing<String>), ClassifiedError> {
        match self.refresh(stale_token, context).await {
            Ok(refreshed) => {
                self.replace_token(&refreshed).await;
                match self.query_usage(refreshed.as_str(), context).await {
                    Ok(parsed) => Ok((parsed, refreshed)),
                    Err(error)
                        if error.kind() == ErrorKind::AuthenticationExpired
                            && self.login.is_some() =>
                    {
                        self.login_and_query(context).await
                    }
                    Err(error) => Err(error),
                }
            }
            Err(_) if self.login.is_some() => self.login_and_query(context).await,
            Err(error) => Err(error),
        }
    }

    async fn login_and_query(
        &self,
        context: &ProviderContext,
    ) -> Result<(ParsedUsage, Zeroizing<String>), ClassifiedError> {
        let login = self.login.as_ref().ok_or_else(api_error)?;
        let token = login
            .transport
            .login(&self.routes, &login.credentials, context.cancellation())
            .await?;
        let parsed = self.query_usage(token.as_str(), context).await?;
        self.replace_token(&token).await;
        Ok((parsed, token))
    }

    async fn replace_token(&self, replacement: &Zeroizing<String>) {
        let mut token = self.token.write().await;
        *token = Zeroizing::new(replacement.as_str().to_owned());
    }

    const fn strategy(&self) -> &'static str {
        if self.login.is_some() {
            "password_login"
        } else {
            "manual_cookie"
        }
    }

    async fn token_copy(&self) -> Zeroizing<String> {
        let token = self.token.read().await;
        Zeroizing::new(token.as_str().to_owned())
    }

    async fn query_usage(
        &self,
        token: &str,
        context: &ProviderContext,
    ) -> Result<ParsedUsage, ClassifiedError> {
        let request = Self::authenticated_post(self.routes.usage.clone(), token, false)?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(classify_required_transport)?;
        if response.status() != 200 {
            return Err(api_error());
        }
        parse_usage(response.body())
    }

    async fn query_plan_name(
        &self,
        token: &str,
        context: &ProviderContext,
    ) -> Result<Option<String>, ClassifiedError> {
        let request = Self::authenticated_post(self.routes.plan_status.clone(), token, false)?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())?;
        if response.status() != 200 {
            return Ok(None);
        }
        parse_plan_name(response.body())
    }

    async fn refresh(
        &self,
        token: &str,
        context: &ProviderContext,
    ) -> Result<Zeroizing<String>, ClassifiedError> {
        let request = Self::authenticated_post(self.routes.refresh.clone(), token, true)?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(classify_refresh_transport)?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        parse_refreshed_token(response.body())
    }

    fn authenticated_post(
        endpoint: Url,
        token: &str,
        token_header: bool,
    ) -> Result<HttpRequest, ClassifiedError> {
        let web_id = web_id_for_token(token);
        let cookie = Zeroizing::new(format!(
            "Oasis-Token={token}; Oasis-Webid={}",
            web_id.as_str()
        ));
        let authentication = Authentication::cookie(cookie.as_str().to_owned())
            .map_err(|error| error.classified())?;
        let mut request = HttpRequest::post_json(endpoint, b"{}".to_vec())
            .and_then(|request| request.public_header("oasis-appid", APP_ID))
            .and_then(|request| request.public_header("oasis-platform", "web"))
            .and_then(|request| request.sensitive_header("oasis-webid", web_id.as_str().to_owned()))
            .and_then(|request| request.public_header("user-agent", USER_AGENT))
            .map_err(|error| error.classified())?
            .authentication(authentication);
        if token_header {
            request = request
                .sensitive_header("oasis-token", token.to_owned())
                .map_err(|error| error.classified())?;
        }
        Ok(request)
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ManualCookie {
            return Err(api_error());
        }
        Ok(())
    }
}

impl ProviderAdapter for StepFunProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::StepFun)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for StepFunProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepFunProvider")
            .field("scope", &"<redacted>")
            .field("source", &ProviderSource::ManualCookie)
            .field("routes", &"<redacted>")
            .field("token", &"<redacted>")
            .field("password_login", &self.login.is_some())
            .field("transport", &"<redacted>")
            .finish()
    }
}

struct PasswordCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl PasswordCredentials {
    fn new(username: &str, password: &str) -> Result<Self, ClassifiedError> {
        validate_login_field(username)?;
        validate_login_field(password)?;
        Ok(Self {
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        })
    }
}

impl Debug for PasswordCredentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordCredentials(<redacted>)")
    }
}

struct StepFunLoginState {
    credentials: PasswordCredentials,
    transport: StepFunLoginTransport,
}

impl Debug for StepFunLoginState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StepFunLoginState(<redacted>)")
    }
}

struct StepFunLoginTransport {
    client: Client,
    policy: EndpointPolicy,
}

impl StepFunLoginTransport {
    fn new(policy: EndpointPolicy) -> Result<Self, ClassifiedError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| api_error())?;
        Ok(Self { client, policy })
    }

    async fn login(
        &self,
        routes: &StepFunRouteSet,
        credentials: &PasswordCredentials,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<String>, ClassifiedError> {
        let ingress = self
            .homepage_ingress_cookie(&routes.homepage, cancellation)
            .await?;
        let anonymous = self
            .register_device(&routes.register_device, &ingress, cancellation)
            .await?;
        self.sign_in(
            &routes.sign_in,
            credentials,
            &ingress,
            &anonymous,
            cancellation,
        )
        .await
    }

    async fn homepage_ingress_cookie(
        &self,
        homepage: &Url,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<String>, ClassifiedError> {
        let mut current = homepage.clone();
        let mut ingress: Option<Zeroizing<String>> = None;
        for redirect_count in 0..=MAX_HOMEPAGE_REDIRECTS {
            let response = self
                .get_homepage(
                    &current,
                    ingress.as_ref().map(|value| value.as_str()),
                    cancellation,
                )
                .await?;
            if response.ingress_cookie.is_some() {
                ingress = response.ingress_cookie;
            }
            if response.status.is_redirection() {
                if redirect_count == MAX_HOMEPAGE_REDIRECTS {
                    return Err(ClassifiedError::new(ErrorKind::Network));
                }
                let location = response.location.ok_or_else(parse_error)?;
                let target = current.join(&location).map_err(|_| parse_error())?;
                self.policy.validate(&target).map_err(|_| api_error())?;
                current = target;
                continue;
            }
            if !response.status.is_success() {
                return Err(classify_login_status(response.status));
            }
            return ingress.ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        Err(ClassifiedError::new(ErrorKind::Network))
    }

    async fn get_homepage(
        &self,
        endpoint: &Url,
        ingress: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<LoginHttpResponse, ClassifiedError> {
        let endpoint = self.policy.validate(endpoint).map_err(|_| api_error())?;
        let web_id = sensitive_header_value(DEFAULT_WEB_ID)?;
        let mut request = self
            .client
            .get(endpoint.url().clone())
            .header(CONTENT_TYPE, "application/json")
            .header("oasis-appid", APP_ID)
            .header("oasis-platform", "web")
            .header("oasis-webid", web_id)
            .header(USER_AGENT_HEADER, USER_AGENT);
        if let Some(ingress) = ingress {
            validate_ingress_cookie(ingress)?;
            let cookie = Zeroizing::new(format!("INGRESSCOOKIE={ingress}"));
            request = request.header(COOKIE, sensitive_header_value(cookie.as_str())?);
        }
        execute_login_request(request, cancellation).await
    }

    async fn register_device(
        &self,
        endpoint: &Url,
        ingress: &str,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<String>, ClassifiedError> {
        let endpoint = self.policy.validate(endpoint).map_err(|_| api_error())?;
        validate_ingress_cookie(ingress)?;
        let cookie = Zeroizing::new(format!("INGRESSCOOKIE={ingress}"));
        let cookie = sensitive_header_value(cookie.as_str())?;
        let web_id = sensitive_header_value(DEFAULT_WEB_ID)?;
        let request = self
            .client
            .post(endpoint.url().clone())
            .header(CONTENT_TYPE, "application/json")
            .header("oasis-appid", APP_ID)
            .header("oasis-platform", "web")
            .header("oasis-webid", web_id)
            .header(USER_AGENT_HEADER, USER_AGENT)
            .header(COOKIE, cookie)
            .body(b"{}".to_vec());
        let response = execute_login_request(request, cancellation).await?;
        require_login_success(&response)?;
        parse_token_response(&response.body, ErrorKind::Api)
    }

    async fn sign_in(
        &self,
        endpoint: &Url,
        credentials: &PasswordCredentials,
        ingress: &str,
        anonymous: &str,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<String>, ClassifiedError> {
        let endpoint = self.policy.validate(endpoint).map_err(|_| api_error())?;
        validate_ingress_cookie(ingress)?;
        validate_token(anonymous)?;
        let web_id = web_id_for_token(anonymous);
        let cookie = Zeroizing::new(format!(
            "Oasis-Token={anonymous}; Oasis-Webid={}; INGRESSCOOKIE={ingress}",
            web_id.as_str()
        ));
        let cookie = sensitive_header_value(cookie.as_str())?;
        let web_id_header = sensitive_header_value(web_id.as_str())?;
        let body = Zeroizing::new(
            serde_json::to_vec(&PasswordLoginBody {
                username: credentials.username.as_str(),
                password: credentials.password.as_str(),
            })
            .map_err(|_| api_error())?,
        );
        let request = self
            .client
            .post(endpoint.url().clone())
            .header(CONTENT_TYPE, "application/json")
            .header("oasis-appid", APP_ID)
            .header("oasis-platform", "web")
            .header("oasis-webid", web_id_header)
            .header(USER_AGENT_HEADER, USER_AGENT)
            .header(COOKIE, cookie)
            .body(body.as_slice().to_vec());
        let response = execute_login_request(request, cancellation).await?;
        require_login_success(&response)?;
        parse_token_response(&response.body, ErrorKind::AuthenticationExpired)
    }
}

impl Debug for StepFunLoginTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StepFunLoginTransport(<redacted>)")
    }
}

#[derive(Serialize)]
struct PasswordLoginBody<'a> {
    username: &'a str,
    password: &'a str,
}

struct LoginHttpResponse {
    status: StatusCode,
    location: Option<String>,
    ingress_cookie: Option<Zeroizing<String>>,
    body: Zeroizing<Vec<u8>>,
}

async fn execute_login_request(
    request: reqwest::RequestBuilder,
    cancellation: &CancellationToken,
) -> Result<LoginHttpResponse, ClassifiedError> {
    let future = async {
        let response = request
            .send()
            .await
            .map_err(|_| ClassifiedError::new(ErrorKind::Network))?;
        read_login_response(response).await
    };
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(ClassifiedError::new(ErrorKind::Network)),
        result = tokio::time::timeout(Duration::from_secs(15), future) => {
            result.unwrap_or_else(|_| Err(ClassifiedError::new(ErrorKind::Network)))
        }
    }
}

async fn read_login_response(response: Response) -> Result<LoginHttpResponse, ClassifiedError> {
    let status = response.status();
    let location = response_location(response.headers())?;
    let ingress_cookie = ingress_cookie_from_headers(response.headers())?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(parse_error());
    }
    let mut body = Zeroizing::new(Vec::new());
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ClassifiedError::new(ErrorKind::Network))?;
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= MAX_RESPONSE_BYTES)
            .ok_or_else(parse_error)?;
        let additional = next_length.saturating_sub(body.len());
        body.reserve(additional);
        body.extend_from_slice(&chunk);
    }
    Ok(LoginHttpResponse {
        status,
        location,
        ingress_cookie,
        body,
    })
}

fn response_location(headers: &HeaderMap) -> Result<Option<String>, ClassifiedError> {
    let Some(location) = headers.get(LOCATION) else {
        return Ok(None);
    };
    if location.as_bytes().len() > MAX_REDIRECT_LOCATION_BYTES {
        return Err(parse_error());
    }
    location
        .to_str()
        .map(str::to_owned)
        .map(Some)
        .map_err(|_| parse_error())
}

fn ingress_cookie_from_headers(
    headers: &HeaderMap,
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let mut selected = None;
    let mut count = 0_usize;
    let mut total_bytes = 0_usize;
    for header in headers.get_all(SET_COOKIE) {
        count = count.checked_add(1).ok_or_else(parse_error)?;
        total_bytes = total_bytes
            .checked_add(header.as_bytes().len())
            .ok_or_else(parse_error)?;
        if count > MAX_SET_COOKIE_HEADERS || total_bytes > MAX_SET_COOKIE_BYTES {
            return Err(parse_error());
        }
        let header = header.to_str().map_err(|_| parse_error())?;
        let Some((_, suffix)) = header.split_once("INGRESSCOOKIE=") else {
            continue;
        };
        let value = suffix
            .split([';', ','])
            .next()
            .map(str::trim)
            .ok_or_else(parse_error)?;
        validate_ingress_cookie(value)?;
        selected = Some(Zeroizing::new(value.to_owned()));
    }
    Ok(selected)
}

fn require_login_success(response: &LoginHttpResponse) -> Result<(), ClassifiedError> {
    if response.status == StatusCode::OK {
        Ok(())
    } else {
        Err(classify_login_status(response.status))
    }
}

fn classify_login_status(status: StatusCode) -> ClassifiedError {
    ClassifiedError::new(
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::Api
        },
    )
}

fn sensitive_header_value(value: &str) -> Result<HeaderValue, ClassifiedError> {
    let mut value = HeaderValue::from_str(value).map_err(|_| api_error())?;
    value.set_sensitive(true);
    Ok(value)
}

fn validate_login_field(value: &str) -> Result<(), ClassifiedError> {
    if value.trim().is_empty()
        || value.len() > MAX_LOGIN_FIELD_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Ok(())
}

fn validate_ingress_cookie(value: &str) -> Result<(), ClassifiedError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b';')
    {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RateLimitResponse {
    status: Option<i64>,
    code: Option<i64>,
    message: Option<String>,
    desc: Option<String>,
    #[serde(rename = "five_hour_usage_left_rate")]
    five_hour_left: Option<FlexibleNumber>,
    #[serde(rename = "weekly_usage_left_rate")]
    weekly_left: Option<FlexibleNumber>,
    #[serde(rename = "five_hour_usage_reset_time")]
    five_hour_reset: Option<FlexibleTimestamp>,
    #[serde(rename = "weekly_usage_reset_time")]
    weekly_reset: Option<FlexibleTimestamp>,
    #[serde(rename = "plan_family")]
    plan_family: Option<FlexibleNumber>,
    #[serde(rename = "plan_credit_rate_limit")]
    credit: Option<CreditLimit>,
}

#[derive(Debug, Clone, Copy)]
struct FlexibleNumber(f64);

impl<'de> Deserialize<'de> for FlexibleNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let parsed = match value {
            Value::Number(value) => value.as_f64().unwrap_or(0.0),
            Value::String(value) => value.parse::<f64>().unwrap_or(0.0),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => 0.0,
        };
        Ok(Self(if parsed.is_finite() { parsed } else { 0.0 }))
    }
}

#[derive(Debug, Clone, Copy)]
struct FlexibleTimestamp(i64);

impl<'de> Deserialize<'de> for FlexibleTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let parsed = match value {
            Value::Number(value) => value.as_i64().unwrap_or(0),
            Value::String(value) => value.parse::<i64>().unwrap_or(0),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => 0,
        };
        Ok(Self(parsed))
    }
}

#[derive(Debug, Deserialize)]
struct CreditLimit {
    #[serde(rename = "subscription_credit_left_rate")]
    subscription_left: Option<FlexibleNumber>,
    #[serde(rename = "subscription_credit_reset_time")]
    subscription_reset: Option<FlexibleTimestamp>,
    #[serde(rename = "topup_credit_left_rate")]
    topup_left: Option<FlexibleNumber>,
    #[serde(rename = "credit_buckets")]
    buckets: Option<Vec<CreditBucket>>,
}

#[derive(Debug, Deserialize)]
struct CreditBucket {
    #[serde(rename = "credit_total")]
    total: Option<FlexibleNumber>,
    #[serde(rename = "credit_residual")]
    residual: Option<FlexibleNumber>,
}

#[derive(Debug)]
struct ParsedUsage {
    five_hour_left: f64,
    weekly_left: f64,
    five_hour_reset: i64,
    weekly_reset: i64,
    credit_left: Option<f64>,
    credit_reset: Option<Timestamp>,
    is_credit_plan: bool,
}

#[derive(Deserialize)]
struct PlanStatusResponse {
    #[serde(rename = "status")]
    _status: Option<i64>,
    subscription: Option<Subscription>,
}

#[derive(Deserialize)]
struct Subscription {
    name: Option<String>,
    #[serde(rename = "plan_type")]
    _plan_type: Option<i64>,
    #[serde(rename = "status")]
    _status: Option<i64>,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(rename = "accessToken")]
    access_token: Option<TokenValue>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<TokenValue>,
}

#[derive(Deserialize)]
struct TokenValue {
    raw: String,
}

/// Parses one `StepFun` usage response into the common model.
///
/// # Errors
///
/// Returns a stable parse, API, authentication, or scope error.
pub fn parse_stepfun_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    plan_name: Option<&str>,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::StepFun {
        return Err(api_error());
    }
    let usage = parse_usage(body)?;
    normalize_usage(scope, fetched_at, &usage, plan_name, "manual_cookie")
}

fn parse_usage(body: &[u8]) -> Result<ParsedUsage, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let decoded: RateLimitResponse = serde_json::from_value(root).map_err(|_| parse_error())?;
    if decoded.status != Some(1) {
        let message = [decoded.message.as_deref(), decoded.desc.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|value| !value.is_empty());
        if decoded.code.is_some_and(|code| matches!(code, 401 | 403))
            || message.is_some_and(is_authentication_message)
        {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        return Err(api_error());
    }

    let five_hour_reset = decoded.five_hour_reset.map_or(0, |value| value.0);
    let weekly_reset = decoded.weekly_reset.map_or(0, |value| value.0);
    let has_live_window = five_hour_reset > 0 || weekly_reset > 0;
    let has_credit_pool = decoded.credit.as_ref().is_some_and(|credit| {
        credit.subscription_left.is_some()
            || credit.topup_left.is_some()
            || credit
                .buckets
                .as_ref()
                .is_some_and(|buckets| !buckets.is_empty())
    });
    let is_credit_plan = if has_live_window {
        false
    } else if has_credit_pool {
        true
    } else {
        decoded
            .plan_family
            .is_some_and(|family| (family.0 - 2.0).abs() < f64::EPSILON)
    };
    if !is_credit_plan
        && (decoded.five_hour_left.is_none()
            || decoded.weekly_left.is_none()
            || decoded.five_hour_reset.is_none()
            || decoded.weekly_reset.is_none())
    {
        return Err(parse_error());
    }

    let credit_left = decoded.credit.as_ref().and_then(total_credit_left_rate);
    let credit_reset = decoded
        .credit
        .as_ref()
        .and_then(|credit| credit.subscription_reset)
        .filter(|reset| reset.0 > 0)
        .and_then(|reset| timestamp_from_unix(reset.0).ok());
    Ok(ParsedUsage {
        five_hour_left: decoded.five_hour_left.map_or(0.0, |value| value.0),
        weekly_left: decoded.weekly_left.map_or(0.0, |value| value.0),
        five_hour_reset,
        weekly_reset,
        credit_left,
        credit_reset,
        is_credit_plan,
    })
}

fn total_credit_left_rate(credit: &CreditLimit) -> Option<f64> {
    if let Some(buckets) = credit
        .buckets
        .as_ref()
        .filter(|buckets| !buckets.is_empty())
    {
        let balances = buckets
            .iter()
            .filter_map(|bucket| {
                let total = bucket.total?.0;
                let residual = bucket.residual?.0;
                (total.is_finite()
                    && residual.is_finite()
                    && total > 0.0
                    && residual >= 0.0
                    && residual <= total)
                    .then_some((total, residual))
            })
            .collect::<Vec<_>>();
        if balances.len() == buckets.len() {
            let (total, residual) = balances.into_iter().fold(
                (0.0_f64, 0.0_f64),
                |(total_sum, residual_sum), (bucket_total, bucket_residual)| {
                    (total_sum + bucket_total, residual_sum + bucket_residual)
                },
            );
            let rate = residual / total;
            if rate.is_finite() {
                return Some(rate);
            }
        }
    }
    credit
        .subscription_left
        .or(credit.topup_left)
        .map(|value| value.0)
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    usage: &ParsedUsage,
    plan_name: Option<&str>,
    strategy: &'static str,
) -> Result<UsageSample, ClassifiedError> {
    let login_method = plan_name
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= MAX_IDENTITY_BYTES)
        .unwrap_or("password");
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some(login_method.to_owned()))?
        .provenance("stepfun", strategy)?;

    if usage.is_credit_plan
        && let Some(credit_left) = usage.credit_left
    {
        let percent = remaining_to_used_percent(credit_left)?;
        let duration = usage
            .credit_reset
            .map(|_| WindowDuration::from_provider_minutes(MONTHLY_MINUTES))
            .transpose()
            .map_err(|_| parse_error())?;
        let window = RateWindow::new(
            WindowUsage::known(percent),
            duration,
            usage.credit_reset,
            None,
            None,
            false,
        )
        .map_err(|_| parse_error())?;
        return builder.primary(window).build();
    }

    let primary = rolling_window(
        usage.five_hour_left,
        usage.five_hour_reset,
        FIVE_HOUR_MINUTES,
    )?;
    let secondary = rolling_window(usage.weekly_left, usage.weekly_reset, WEEKLY_MINUTES)?;
    builder = builder.primary(primary).secondary(secondary);
    builder.build()
}

fn rolling_window(remaining: f64, reset: i64, minutes: i64) -> Result<RateWindow, ClassifiedError> {
    let percent = remaining_to_used_percent(remaining)?;
    let duration = WindowDuration::from_provider_minutes(minutes).map_err(|_| parse_error())?;
    let reset = timestamp_from_unix(reset)?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        Some(reset),
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn remaining_to_used_percent(remaining: f64) -> Result<UsagePercent, ClassifiedError> {
    if !remaining.is_finite() {
        return Err(parse_error());
    }
    UsagePercent::new(((1.0 - remaining) * 100.0).clamp(0.0, 100.0)).map_err(|_| parse_error())
}

fn parse_plan_name(body: &[u8]) -> Result<Option<String>, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let response: PlanStatusResponse = serde_json::from_value(root).map_err(|_| parse_error())?;
    Ok(response.subscription.and_then(|subscription| {
        subscription.name.and_then(|name| {
            let trimmed = name.trim();
            (!trimmed.is_empty()
                && trimmed.len() <= MAX_IDENTITY_BYTES
                && !trimmed.chars().any(char::is_control))
            .then(|| trimmed.to_owned())
        })
    }))
}

fn parse_refreshed_token(body: &[u8]) -> Result<Zeroizing<String>, ClassifiedError> {
    parse_token_response(body, ErrorKind::AuthenticationExpired)
}

fn parse_token_response(
    body: &[u8],
    missing_kind: ErrorKind,
) -> Result<Zeroizing<String>, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let response: TokenResponse = serde_json::from_value(root).map_err(|_| parse_error())?;
    let access = response
        .access_token
        .map(|token| Zeroizing::new(token.raw))
        .filter(|token| validate_token(token.as_str()).is_ok())
        .ok_or_else(|| ClassifiedError::new(missing_kind))?;
    let Some(refresh) = response
        .refresh_token
        .map(|token| Zeroizing::new(token.raw))
        .filter(|token| validate_token(token.as_str()).is_ok())
    else {
        return Ok(access);
    };
    let combined = Zeroizing::new(format!("{}...{}", access.as_str(), refresh.as_str()));
    validate_token(combined.as_str())?;
    Ok(combined)
}

fn token_from_manual_input(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let candidate = Zeroizing::new(if raw.starts_with("curl ") || raw.starts_with("curl\t") {
        let policy = ManualCapturePolicy::new(["platform.stepfun.com"], [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?
            .to_owned()
    } else {
        raw.strip_prefix("Cookie:")
            .or_else(|| raw.strip_prefix("cookie:"))
            .map_or(raw, str::trim)
            .to_owned()
    });
    normalize_token(candidate.as_str())
}

fn normalize_token(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = value[1..value.len() - 1].trim();
    }
    if let Some((_, suffix)) = value.split_once("Oasis-Token=") {
        value = suffix.split(';').next().unwrap_or(suffix).trim();
    }
    validate_token(value)?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn validate_token(token: &str) -> Result<(), ClassifiedError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b';')
    {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Authentication::cookie(format!("Oasis-Token={token}"))
        .map(|_| ())
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))
}

fn web_id_for_token(token: &str) -> Zeroizing<String> {
    for half in token.rsplit("...") {
        if let Some(device_id) = extract_device_id(half) {
            return Zeroizing::new(device_id);
        }
    }
    Zeroizing::new(DEFAULT_WEB_ID.to_owned())
}

fn extract_device_id(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    if payload.is_empty() || payload.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    if decoded.len() > MAX_JSON_STRING_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    let device_id = value.get("device_id")?.as_str()?.trim();
    if device_id.is_empty()
        || device_id.len() > MAX_IDENTITY_BYTES
        || device_id
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b';')
    {
        return None;
    }
    Some(device_id.to_owned())
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| parse_error())?;
    let mut stack = vec![(&root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(parse_error)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(parse_error());
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.keys().any(|key| key.len() > MAX_JSON_KEY_BYTES) {
                    return Err(parse_error());
                }
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(parse_error());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(root)
}

fn fixed_url(mut origin: Url, path: &str) -> Result<Url, ClassifiedError> {
    if origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.fragment().is_some()
    {
        return Err(api_error());
    }
    origin.set_path(path);
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin)
}

fn is_authentication_message(message: &str) -> bool {
    let message = message.trim().to_ascii_lowercase();
    message.contains("401")
        || message.contains("403")
        || message.contains("unauthorized")
        || message.contains("unauthenticated")
        || message.contains("invalid credentials")
        || message.contains("invalid token")
        || message.contains("token expired")
        || message.contains("expired token")
}

fn classify_required_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        TransportError::RequestTimeout
        | TransportError::RateLimited { .. }
        | TransportError::ProviderUnavailable { .. }
        | TransportError::Api { .. } => api_error(),
        TransportError::TooManyRedirects => ClassifiedError::new(ErrorKind::Network),
        other => other.classified(),
    }
}

fn classify_refresh_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        other => classify_required_transport(other),
    }
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    let kind = match error {
        ManualCaptureError::MissingSecret
        | ManualCaptureError::InvalidSecret
        | ManualCaptureError::DisallowedHeader => ErrorKind::MissingCredential,
        ManualCaptureError::InputTooLarge
        | ManualCaptureError::InvalidSyntax
        | ManualCaptureError::UnsafeSyntax
        | ManualCaptureError::UnsafeOption
        | ManualCaptureError::TooManyTokens
        | ManualCaptureError::TooManyHeaders
        | ManualCaptureError::DuplicateSecret
        | ManualCaptureError::ConflictingHeader
        | ManualCaptureError::DisallowedUrl => ErrorKind::Parse,
        ManualCaptureError::InvalidPolicy => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        5,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}
