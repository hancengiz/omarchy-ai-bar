//! IBM Bob monthly Bobcoin usage across subscription teams.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowDuration,
    WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "BOBSHELL_API_KEY";
const DEFAULT_API_URL: &str = "https://api.us-east.bob.ibm.com";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEAMS: usize = 24;
const MONTHLY_MINUTES: i64 = 30 * 24 * 60;
const CLIENT_NAME: &str = "omarchy-ai-bar";

/// Validated IBM Bob credential and authorization style.
pub struct IBMBobSettings {
    credential: ApiKeyCredential,
    bearer: bool,
}

impl IBMBobSettings {
    /// Resolves `BOBSHELL_API_KEY` and detects Bob session JWTs.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for absent or invalid input.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let bearer = credential.is_structured_jwt();
        Ok(Self { credential, bearer })
    }
}

impl Debug for IBMBobSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IBMBobSettings")
            .field("credential", &"<redacted>")
            .field(
                "authorization",
                &if self.bearer { "bearer" } else { "api-key" },
            )
            .finish()
    }
}

/// Native IBM Bob provider adapter.
pub struct IBMBobProvider {
    profile_client: FixedApiClient,
}

impl IBMBobProvider {
    /// Creates the production US-East profile client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: IBMBobSettings) -> Result<Self, ClassifiedError> {
        let base_url =
            Url::parse(DEFAULT_API_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let config = transport_config()?;
        let profile_client = if settings.bearer {
            FixedApiClient::new_bearer(
                scope,
                base_url,
                EndpointClass::PublicHttps,
                settings.credential,
                config,
            )?
        } else {
            FixedApiClient::new_authorization_scheme(
                scope,
                base_url,
                EndpointClass::PublicHttps,
                "Apikey",
                settings.credential,
                config,
            )?
        };
        Self::from_client(profile_client)
    }

    /// Wraps an already validated account-scoped profile client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider.
    pub fn from_client(profile_client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if profile_client.scope().provider() != ProviderId::IbmBob {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { profile_client })
    }

    /// Validates one provider-discovered regional domain without credentials.
    ///
    /// # Errors
    ///
    /// Rejects URL components, ports, and hosts outside `bob.ibm.com`.
    pub fn trusted_region_url(region_domain: &str) -> Result<Url, ClassifiedError> {
        trusted_region_url(region_domain)
    }

    /// Fetches and aggregates every usable team from the profile.
    ///
    /// # Errors
    ///
    /// Returns stable classified transport, discovery, or parse errors without
    /// provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let profile_url = self.profile_client.url("admin/v1/profile")?;
        let profile: ProfileResponse = self
            .profile_client
            .get_json_with_public_headers(context, profile_url, &[("user-agent", CLIENT_NAME)])
            .await?
            .json()?;

        let usable_team_count = profile
            .instances
            .iter()
            .try_fold(0_usize, |total, instance| {
                if non_empty(instance.user_id.as_deref()).is_none() {
                    return Ok(total);
                }
                let count = instance
                    .teams
                    .iter()
                    .filter(|team| non_empty(Some(team.id.as_str())).is_some())
                    .count();
                total
                    .checked_add(count)
                    .filter(|count| *count <= MAX_TEAMS)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
            })?;
        if usable_team_count == 0 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }

        let mut teams = Vec::new();
        for instance in profile.instances {
            let Some(user_id) = non_empty(instance.user_id.as_deref()) else {
                continue;
            };
            let regional_client = match non_empty(instance.region_domain.as_deref()) {
                Some(domain) => self
                    .profile_client
                    .rebind(trusted_region_url(domain)?, EndpointClass::PublicHttps)?,
                None => self.profile_client.rebind(
                    self.profile_client.base_url().clone(),
                    endpoint_class_for_existing(self.profile_client.base_url())?,
                )?,
            };
            for team in &instance.teams {
                let Some(team_id) = non_empty(Some(team.id.as_str())) else {
                    continue;
                };
                let url = team_budget_url(regional_client.base_url(), team_id, user_id)?;
                let budget: TeamBudgetResponse = regional_client
                    .get_json_with_public_headers(
                        context,
                        url,
                        &[
                            ("user-agent", CLIENT_NAME),
                            ("x-instance-id", instance.id.as_str()),
                            ("x-team-id", team_id),
                        ],
                    )
                    .await?
                    .json()?;
                let limit = budget
                    .budget_limit
                    .or(team.budget_limit)
                    .map(|value| value.0)
                    .filter(|value| *value >= Decimal::ZERO);
                teams.push(TeamUsage {
                    instance_name: non_empty(instance.name())
                        .unwrap_or(&instance.id)
                        .to_owned(),
                    team_name: non_empty(team.name.as_deref())
                        .unwrap_or(team_id)
                        .to_owned(),
                    plan_name: non_empty(instance.plan_name.as_deref()).map(str::to_owned),
                    used: budget.usage.0.max(Decimal::ZERO),
                    limit,
                    resets_at: parse_refresh(instance.refresh_at.as_ref()),
                });
            }
        }
        normalize(context.scope().clone(), fetched_at, &teams)
    }
}

impl ProviderAdapter for IBMBobProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::IbmBob)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct ProfileResponse {
    instances: Vec<Instance>,
}

#[derive(Deserialize)]
struct Instance {
    #[serde(rename = "instance_id")]
    id: String,
    #[serde(rename = "instance_name")]
    display_name: Option<String>,
    name: Option<String>,
    user_id: Option<String>,
    plan_name: Option<String>,
    refresh_at: Option<RefreshAt>,
    region_domain: Option<String>,
    teams: Vec<Team>,
}

impl Instance {
    fn name(&self) -> Option<&str> {
        self.display_name.as_deref().or(self.name.as_deref())
    }
}

#[derive(Deserialize)]
struct Team {
    id: String,
    name: Option<String>,
    budget_limit: Option<JsonDecimal>,
    #[serde(rename = "usage")]
    _usage: Option<JsonDecimal>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RefreshAt {
    Seconds(JsonDecimal),
    Text(String),
}

#[derive(Deserialize)]
struct TeamBudgetResponse {
    usage: JsonDecimal,
    budget_limit: Option<JsonDecimal>,
}

#[derive(Clone, Copy)]
struct JsonDecimal(Decimal);

impl<'de> Deserialize<'de> for JsonDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        let raw = number.to_string();
        Decimal::from_scientific(&raw)
            .or_else(|_| raw.parse())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

struct TeamUsage {
    instance_name: String,
    team_name: String,
    plan_name: Option<String>,
    used: Decimal,
    limit: Option<Decimal>,
    resets_at: Option<Timestamp>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    teams: &[TeamUsage],
) -> Result<UsageSample, ClassifiedError> {
    let used = teams.iter().try_fold(Decimal::ZERO, |total, team| {
        total
            .checked_add(team.used)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
    })?;
    let limit = teams
        .iter()
        .map(|team| team.limit)
        .collect::<Option<Vec<_>>>()
        .map(|limits| {
            limits.into_iter().try_fold(Decimal::ZERO, |total, limit| {
                total
                    .checked_add(limit)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
            })
        })
        .transpose()?;
    let reset = teams.iter().filter_map(|team| team.resets_at).min();
    let percent = match limit.filter(|limit| *limit > Decimal::ZERO) {
        Some(limit) => percentage(used, limit)?,
        None => 0.0,
    };
    let summary = limit.map_or_else(
        || format!("{} Bobcoins used", format_bobcoins(used)),
        |limit| {
            format!(
                "{} / {} Bobcoins",
                format_bobcoins(used),
                format_bobcoins(limit)
            )
        },
    );
    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(
            WindowDuration::from_provider_minutes(MONTHLY_MINUTES)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        reset,
        Some(BoundedText::new(summary).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;

    let rows = teams
        .iter()
        .map(|team| {
            let label = if team.team_name == team.instance_name {
                team.team_name.clone()
            } else {
                format!("{} · {}", team.instance_name, team.team_name)
            };
            let value = team.limit.map_or_else(
                || format!("{} Bobcoins used", format_bobcoins(team.used)),
                |limit| {
                    format!(
                        "{} / {} Bobcoins",
                        format_bobcoins(team.used),
                        format_bobcoins(limit)
                    )
                },
            );
            DetailRow::new(
                label,
                value,
                team.plan_name.clone(),
                DetailSensitivity::Personal,
            )
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let details = DetailSection::new(Some("Bobcoin usage".to_owned()), rows, None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let plans = teams
        .iter()
        .filter_map(|team| team.plan_name.as_ref())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");

    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .organization((!plans.is_empty()).then_some(plans))?
        .login_method(Some("API key".to_owned()))?
        .detail_sections(vec![details])
        .provenance("ibmbob", "api")?
        .build()
}

fn percentage(used: Decimal, limit: Decimal) -> Result<f64, ClassifiedError> {
    used.checked_mul(Decimal::from(100_u8))
        .and_then(|value| value.checked_div(limit))
        .and_then(|value| value.to_f64())
        .map(|value| value.clamp(0.0, 100.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn format_bobcoins(value: Decimal) -> String {
    if value.fract().is_zero() {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    }
}

fn parse_refresh(value: Option<&RefreshAt>) -> Option<Timestamp> {
    match value? {
        RefreshAt::Seconds(seconds) if seconds.0 > Decimal::ZERO => seconds
            .0
            .trunc()
            .to_i64()
            .and_then(|seconds| Timestamp::from_unix_timestamp(seconds).ok()),
        RefreshAt::Text(text) => {
            non_empty(Some(text.as_str())).and_then(|text| Timestamp::parse(text).ok())
        }
        RefreshAt::Seconds(_) => None,
    }
}

fn trusted_region_url(region_domain: &str) -> Result<Url, ClassifiedError> {
    let domain =
        non_empty(Some(region_domain)).ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if domain.contains(':') {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let host = if domain.to_ascii_lowercase().starts_with("api.") {
        domain.to_owned()
    } else {
        format!("api.{domain}")
    };
    let url =
        Url::parse(&format!("https://{host}")).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let parsed_host = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !(parsed_host == "bob.ibm.com" || parsed_host.ends_with(".bob.ibm.com"))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(url)
}

fn team_budget_url(base: &Url, team_id: &str, user_id: &str) -> Result<Url, ClassifiedError> {
    let mut url = base.clone();
    let mut path = url
        .path_segments_mut()
        .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
    path.pop_if_empty();
    for segment in ["admin", "v1", "teams", team_id, "users", user_id] {
        path.push(segment);
    }
    drop(path);
    Ok(url)
}

fn endpoint_class_for_existing(url: &Url) -> Result<EndpointClass, ClassifiedError> {
    if url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    {
        Ok(EndpointClass::LoopbackDevelopment)
    } else if url.scheme() == "https" {
        Ok(EndpointClass::PublicHttps)
    } else {
        Err(ClassifiedError::new(ErrorKind::Api))
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(20),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
