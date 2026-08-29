//! Warp monthly and add-on credit usage through its GraphQL API.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, count_percent, count_window, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://app.warp.dev/";
const KEY_NAMES: [&str; 2] = ["WARP_API_KEY", "WARP_TOKEN"];
const CLIENT_ID: &str = "warp-app";
const USER_AGENT: &str = "Warp/1.0";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PLATFORM_TEXT_BYTES: usize = 128;

const GRAPHQL_QUERY: &str = r"query GetRequestLimitInfo($requestContext: RequestContext!) {
  user(requestContext: $requestContext) {
    __typename
    ... on UserOutput {
      user {
        requestLimitInfo {
          isUnlimited
          nextRefreshTime
          requestLimit
          requestsUsedSinceLastRefresh
        }
        bonusGrants {
          requestCreditsGranted
          requestCreditsRemaining
          expiration
        }
        workspaces {
          bonusGrantsInfo {
            grants {
              requestCreditsGranted
              requestCreditsRemaining
              expiration
            }
          }
        }
      }
    }
  }
}";

/// Native Warp provider adapter.
pub struct WarpProvider {
    client: FixedApiClient,
    platform: PlatformMetadata,
}

impl WarpProvider {
    /// Resolves the baseline API-key precedence from an environment snapshot.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when neither key is usable.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &KEY_NAMES)
    }

    /// Creates the production fixed-origin GraphQL client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, credential: ApiKeyCredential) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            credential,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// Linux metadata mirrors Warp's macOS client context. On Omarchy, the
    /// distribution name and version come from `/etc/os-release`.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Warp {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            client,
            platform: PlatformMetadata::detect(),
        })
    }

    /// Fetches and normalizes one deterministic sample timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable classified transport, GraphQL, or parse errors without
    /// provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let mut url = self.client.url("graphql/v2")?;
        url.query_pairs_mut()
            .append_pair("op", "GetRequestLimitInfo");
        let body = request_body(&self.platform)?;
        let headers = [
            ("x-warp-client-id", CLIENT_ID),
            ("x-warp-os-category", self.platform.category.as_str()),
            ("x-warp-os-name", self.platform.name.as_str()),
            ("x-warp-os-version", self.platform.version.as_str()),
            ("user-agent", USER_AGENT),
        ];
        let response = self
            .client
            .post_json_with_public_headers(context, url, body, &headers)
            .await?;
        let payload: GraphQlResponse = response.json()?;
        normalize(context.scope().clone(), fetched_at, payload)
    }
}

impl ProviderAdapter for WarpProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Warp)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct PlatformMetadata {
    category: String,
    name: String,
    version: String,
}

impl PlatformMetadata {
    fn detect() -> Self {
        let category = if cfg!(target_os = "linux") {
            "Linux"
        } else {
            std::env::consts::OS
        };
        let mut name = category.to_owned();
        let mut version = "unknown".to_owned();
        if cfg!(target_os = "linux")
            && let Ok(contents) = fs::read_to_string("/etc/os-release")
        {
            name = os_release_value(&contents, "NAME").unwrap_or(name);
            version = os_release_value(&contents, "VERSION_ID").unwrap_or(version);
        }
        Self {
            category: category.to_owned(),
            name,
            version,
        }
    }
}

fn os_release_value(contents: &str, key: &str) -> Option<String> {
    let value = contents.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then_some(value)
    })?;
    let value = value.trim();
    let value = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    (!value.is_empty()
        && value.len() <= MAX_PLATFORM_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' '))
    .then(|| value.to_owned())
}

fn request_body(platform: &PlatformMetadata) -> Result<Vec<u8>, ClassifiedError> {
    serde_json::to_vec(&json!({
        "query": GRAPHQL_QUERY,
        "variables": {
            "requestContext": {
                "clientContext": {},
                "osContext": {
                    "category": platform.category,
                    "name": platform.name,
                    "version": platform.version,
                }
            }
        },
        "operationName": "GetRequestLimitInfo",
    }))
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

#[derive(Deserialize)]
struct GraphQlResponse {
    data: Option<GraphQlData>,
    errors: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct GraphQlData {
    user: Option<UserResult>,
}

#[derive(Deserialize)]
struct UserResult {
    #[serde(rename = "__typename")]
    _type_name: Option<String>,
    user: Option<User>,
}

#[derive(Deserialize)]
struct User {
    #[serde(rename = "requestLimitInfo")]
    request_limit_info: Option<RequestLimitInfo>,
    #[serde(rename = "bonusGrants")]
    bonus_grants: Option<Vec<BonusGrant>>,
    workspaces: Option<Vec<Workspace>>,
}

#[derive(Deserialize)]
struct RequestLimitInfo {
    #[serde(rename = "isUnlimited")]
    is_unlimited: Option<Value>,
    #[serde(rename = "nextRefreshTime")]
    next_refresh_time: Option<String>,
    #[serde(rename = "requestLimit")]
    request_limit: Option<Value>,
    #[serde(rename = "requestsUsedSinceLastRefresh")]
    requests_used: Option<Value>,
}

#[derive(Deserialize)]
struct Workspace {
    #[serde(rename = "bonusGrantsInfo")]
    bonus_grants_info: Option<BonusGrantsInfo>,
}

#[derive(Deserialize)]
struct BonusGrantsInfo {
    grants: Option<Vec<BonusGrant>>,
}

#[derive(Deserialize)]
struct BonusGrant {
    #[serde(rename = "requestCreditsGranted")]
    granted: Option<Value>,
    #[serde(rename = "requestCreditsRemaining")]
    remaining: Option<Value>,
    expiration: Option<String>,
}

struct BonusSummary {
    remaining: i64,
    total: i64,
    next_expiration: Option<Timestamp>,
    next_expiration_remaining: i64,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: GraphQlResponse,
) -> Result<UsageSample, ClassifiedError> {
    if response
        .errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let user_result = response
        .data
        .and_then(|data| data.user)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let Some(user) = user_result.user else {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    };
    let limit = user
        .request_limit_info
        .as_ref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let is_unlimited = bool_value(limit.is_unlimited.as_ref());
    let request_limit = int_value(limit.request_limit.as_ref());
    let requests_used = int_value(limit.requests_used.as_ref());
    let resets_at = if is_unlimited {
        None
    } else {
        limit
            .next_refresh_time
            .as_deref()
            .and_then(|value| Timestamp::parse(value).ok())
    };
    let primary = if is_unlimited {
        RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(0.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            None,
            None,
            Some(
                BoundedText::new("Unlimited")
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
    } else {
        count_window(
            requests_used,
            request_limit,
            resets_at,
            Some(format!("{requests_used}/{request_limit} credits")),
        )?
    };
    let bonus = bonus_summary(&user)?;
    let secondary = bonus_window(&bonus)?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at).primary(primary);
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("warp", "api")?.build()
}

fn bonus_summary(user: &User) -> Result<BonusSummary, ClassifiedError> {
    let grants = user
        .bonus_grants
        .iter()
        .flatten()
        .chain(
            user.workspaces
                .iter()
                .flatten()
                .filter_map(|workspace| workspace.bonus_grants_info.as_ref())
                .flat_map(|info| info.grants.iter().flatten()),
        )
        .map(|grant| {
            (
                int_value(grant.granted.as_ref()),
                int_value(grant.remaining.as_ref()),
                grant
                    .expiration
                    .as_deref()
                    .and_then(|value| Timestamp::parse(value).ok()),
            )
        })
        .collect::<Vec<_>>();
    let total = grants.iter().try_fold(0_i64, |total, grant| {
        total
            .checked_add(grant.0)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
    })?;
    let remaining = grants.iter().try_fold(0_i64, |total, grant| {
        total
            .checked_add(grant.1)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
    })?;
    let next_expiration = grants
        .iter()
        .filter(|grant| grant.1 > 0)
        .filter_map(|grant| grant.2)
        .min();
    let next_expiration_second = next_expiration.map(Timestamp::unix_timestamp);
    let next_expiration_remaining = grants
        .iter()
        .filter(|grant| {
            grant.1 > 0
                && grant.2.map(Timestamp::unix_timestamp) == next_expiration_second
                && next_expiration_second.is_some()
        })
        .try_fold(0_i64, |total, grant| {
            total
                .checked_add(grant.1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
        })?;
    Ok(BonusSummary {
        remaining,
        total,
        next_expiration,
        next_expiration_remaining,
    })
}

fn bonus_window(bonus: &BonusSummary) -> Result<Option<RateWindow>, ClassifiedError> {
    let detail = match (bonus.next_expiration, bonus.next_expiration_remaining) {
        (Some(expiration), remaining) if remaining > 0 => {
            Some(format!("{remaining} credits expires on {expiration}"))
        }
        _ => None,
    };
    if bonus.total <= 0 && bonus.remaining <= 0 && detail.is_none() {
        return Ok(None);
    }
    let used_percent = if bonus.total > 0 {
        let used = bonus
            .total
            .checked_sub(bonus.remaining)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        count_percent(used, bonus.total)?
    } else if bonus.remaining > 0 {
        UsagePercent::new(0.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
    } else {
        UsagePercent::new(100.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
    };
    let detail = detail
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(used_percent),
        None,
        None,
        detail,
        None,
        false,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn int_value(value: Option<&Value>) -> i64 {
    let Some(value) = value else {
        return 0;
    };
    match value {
        Value::Number(number) => number
            .to_string()
            .parse::<Decimal>()
            .ok()
            .and_then(|value| value.trunc().to_i64())
            .unwrap_or(0),
        Value::String(value) => value.parse().unwrap_or(0),
        _ => 0,
    }
}

fn bool_value(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes"
        ),
        _ => false,
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
