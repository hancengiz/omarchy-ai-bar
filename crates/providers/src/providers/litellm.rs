//! `LiteLLM` virtual-key spend and budget adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use url::Url;

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "LITELLM_API_KEY";
const BASE_URL: &str = "LITELLM_BASE_URL";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_TEAMS: usize = 256;

/// Validated `LiteLLM` endpoint and virtual-key credential.
pub struct LiteLlmSettings {
    credential: ApiKeyCredential,
    endpoint: ConfiguredEndpoint,
}

impl LiteLlmSettings {
    /// Resolves the baseline environment settings.
    ///
    /// HTTPS is accepted for any valid host. Plain HTTP is accepted only for
    /// loopback, RFC 1918/link-local/IPv6-local addresses, and `.local` hosts.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or endpoint configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let raw = environment
            .get(BASE_URL)
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::PrivateNetworkHttp)?;
        Ok(Self {
            credential,
            endpoint,
        })
    }
}

impl Debug for LiteLlmSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiteLlmSettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Native `LiteLLM` provider adapter.
pub struct LiteLlmProvider {
    client: FixedApiClient,
    endpoint: ConfiguredEndpoint,
}

impl LiteLlmProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: LiteLlmSettings) -> Result<Self, ClassifiedError> {
        let LiteLlmSettings {
            credential,
            endpoint,
        } = settings;
        let client = FixedApiClient::new_bearer(
            scope,
            endpoint.url().clone(),
            endpoint.class(),
            credential,
            transport_config()?,
        )?;
        Self::from_client(client, endpoint)
    }

    /// Wraps an already validated account-scoped client and matching endpoint.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider or a mismatched base.
    pub fn from_client(
        client: FixedApiClient,
        endpoint: ConfiguredEndpoint,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::LiteLlm || client.base_url() != endpoint.url() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client, endpoint })
    }

    /// Fetches and normalizes one deterministic sample timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable classified transport or parse errors without provider
    /// response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let key_url = self.endpoint.path(Some("v1"), &["key", "info"])?;
        let response: KeyInfoResponse = self.client.get_json(context, key_url).await?.json()?;
        let key = ParsedKeyInfo::from_response(response)?;

        if let Some(user_id) = key.user_id.as_deref() {
            let user_url = self.info_url("user", "user_id", user_id)?;
            let response: UserInfoResponse =
                self.client.get_json(context, user_url).await?.json()?;
            return normalize_user(context.scope().clone(), fetched_at, &key, &response);
        }
        if let Some(team_id) = key.team_id.as_deref() {
            let team_url = self.info_url("team", "team_id", team_id)?;
            let response: TeamInfoResponse =
                self.client.get_json(context, team_url).await?.json()?;
            return normalize_team(context.scope().clone(), fetched_at, &key, &response);
        }
        Err(ClassifiedError::new(ErrorKind::Parse))
    }

    fn info_url(&self, kind: &str, query_name: &str, id: &str) -> Result<Url, ClassifiedError> {
        let mut url = self.endpoint.path(Some("v1"), &[kind, "info"])?;
        url.query_pairs_mut().append_pair(query_name, id);
        Ok(url)
    }
}

impl ProviderAdapter for LiteLlmProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::LiteLlm)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct KeyInfoResponse {
    info: KeyInfo,
}

#[derive(Deserialize)]
struct KeyInfo {
    #[serde(rename = "key_name")]
    _key_name: Option<String>,
    #[serde(rename = "spend")]
    _spend: Option<JsonDecimal>,
    expires: Option<String>,
    user_id: Option<String>,
    team_id: Option<String>,
}

struct ParsedKeyInfo {
    user_id: Option<String>,
    team_id: Option<String>,
    expires_at: Option<Timestamp>,
}

impl ParsedKeyInfo {
    fn from_response(response: KeyInfoResponse) -> Result<Self, ClassifiedError> {
        let user_id = clean_identifier(response.info.user_id)?;
        let team_id = clean_identifier(response.info.team_id)?;
        if user_id.is_none() && team_id.is_none() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(Self {
            user_id,
            team_id,
            expires_at: parse_optional_timestamp(response.info.expires.as_deref()),
        })
    }
}

#[derive(Deserialize)]
struct UserInfoResponse {
    user_id: Option<String>,
    user_info: UserInfo,
    teams: Option<Vec<Team>>,
}

#[derive(Deserialize)]
struct UserInfo {
    user_id: Option<String>,
    user_alias: Option<String>,
    max_budget: Option<JsonDecimal>,
    spend: Option<JsonDecimal>,
    user_email: Option<String>,
    budget_reset_at: Option<String>,
    metadata: Option<UserMetadata>,
}

#[derive(Deserialize)]
struct UserMetadata {
    preferred_username: Option<String>,
}

#[derive(Deserialize)]
struct Team {
    #[serde(rename = "team_alias")]
    alias: Option<String>,
    #[serde(rename = "team_id")]
    id: String,
    max_budget: Option<JsonDecimal>,
    spend: Option<JsonDecimal>,
    budget_reset_at: Option<String>,
    #[serde(rename = "budget_duration")]
    _budget_duration: Option<String>,
}

#[derive(Deserialize)]
struct TeamInfoResponse {
    team_id: Option<String>,
    team_info: TeamInfo,
}

#[derive(Deserialize)]
struct TeamInfo {
    team_alias: Option<String>,
    team_id: Option<String>,
    max_budget: Option<JsonDecimal>,
    spend: Option<JsonDecimal>,
    budget_reset_at: Option<String>,
    #[serde(rename = "budget_duration")]
    _budget_duration: Option<String>,
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

struct NormalizedTeam {
    alias: Option<String>,
    spend: Decimal,
    budget: Option<Decimal>,
    resets_at: Option<Timestamp>,
}

fn normalize_user(
    scope: AccountScope,
    fetched_at: Timestamp,
    key: &ParsedKeyInfo,
    response: &UserInfoResponse,
) -> Result<UsageSample, ClassifiedError> {
    let expected_user_id = key
        .user_id
        .as_deref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if let Some(response_user_id) = response
        .user_info
        .user_id
        .as_deref()
        .or(response.user_id.as_deref())
        && response_user_id != expected_user_id
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if response
        .teams
        .as_ref()
        .is_some_and(|teams| teams.len() > MAX_TEAMS)
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let email = first_non_empty([
        response.user_info.user_email.as_deref(),
        response.user_info.user_alias.as_deref(),
        response
            .user_info
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.preferred_username.as_deref()),
    ]);
    let personal_spend = response
        .user_info
        .spend
        .map_or(Decimal::ZERO, |value| value.0);
    let personal_budget = response.user_info.max_budget.map(|value| value.0);
    let personal_reset = parse_optional_timestamp(response.user_info.budget_reset_at.as_deref());
    let team = preferred_team(response.teams.as_deref(), key.team_id.as_deref())?;

    let primary = budget_window(
        personal_spend,
        personal_budget,
        personal_reset,
        BudgetOwner::Personal,
    )?;
    let secondary = team
        .as_ref()
        .map(|team| {
            budget_window(
                team.spend,
                team.budget,
                team.resets_at,
                BudgetOwner::Team(team.alias.as_deref()),
            )
        })
        .transpose()?
        .flatten();
    let cost = cost_summary(
        personal_spend,
        personal_budget,
        personal_reset,
        "Personal",
        fetched_at,
    )?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(cost) = cost {
        builder = builder.cost(cost);
    }
    builder
        .email(email)?
        .organization(team.and_then(|team| team.alias))?
        .login_method(Some("api".to_owned()))?
        .subscription_expires_at(key.expires_at)
        .provenance("litellm", "api")?
        .build()
}

fn normalize_team(
    scope: AccountScope,
    fetched_at: Timestamp,
    key: &ParsedKeyInfo,
    response: &TeamInfoResponse,
) -> Result<UsageSample, ClassifiedError> {
    let expected_team_id = key
        .team_id
        .as_deref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let response_team_id = first_non_empty([
        response.team_info.team_id.as_deref(),
        response.team_id.as_deref(),
    ]);
    if response_team_id
        .as_deref()
        .is_some_and(|id| id != expected_team_id)
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let alias = clean_optional_text(response.team_info.team_alias.as_deref());
    let spend = response
        .team_info
        .spend
        .map_or(Decimal::ZERO, |value| value.0);
    let budget = response.team_info.max_budget.map(|value| value.0);
    let resets_at = parse_optional_timestamp(response.team_info.budget_reset_at.as_deref());
    let secondary = budget_window(
        spend,
        budget,
        resets_at,
        BudgetOwner::Team(alias.as_deref()),
    )?;
    let cost = cost_summary(spend, budget, resets_at, "Team", fetched_at)?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(cost) = cost {
        builder = builder.cost(cost);
    }
    builder
        .organization(alias)?
        .login_method(Some("api".to_owned()))?
        .subscription_expires_at(key.expires_at)
        .provenance("litellm", "api")?
        .build()
}

fn preferred_team(
    teams: Option<&[Team]>,
    expected_team_id: Option<&str>,
) -> Result<Option<NormalizedTeam>, ClassifiedError> {
    let (Some(teams), Some(expected_team_id)) = (teams, expected_team_id) else {
        return Ok(None);
    };
    let Some(team) = teams.iter().find(|team| team.id == expected_team_id) else {
        return Ok(None);
    };
    if team.id.len() > MAX_IDENTIFIER_BYTES || team.id.contains(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(Some(NormalizedTeam {
        alias: clean_optional_text(team.alias.as_deref()),
        spend: team.spend.map_or(Decimal::ZERO, |value| value.0),
        budget: team.max_budget.map(|value| value.0),
        resets_at: parse_optional_timestamp(team.budget_reset_at.as_deref()),
    }))
}

#[derive(Clone, Copy)]
enum BudgetOwner<'a> {
    Personal,
    Team(Option<&'a str>),
}

fn budget_window(
    spend: Decimal,
    budget: Option<Decimal>,
    resets_at: Option<Timestamp>,
    owner: BudgetOwner<'_>,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let Some(budget) = budget.filter(|value| *value > Decimal::ZERO) else {
        return Ok(None);
    };
    let percent = spend
        .checked_mul(Decimal::from(100_u8))
        .and_then(|value| value.checked_div(budget))
        .and_then(|value| value.to_f64())
        .map(|value| value.clamp(0.0, 100.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let description = match owner {
        BudgetOwner::Team(alias) => {
            let label = alias.map_or_else(|| "Team".to_owned(), |alias| format!("Team {alias}"));
            format!("{label}: {} / {}", format_usd(spend), format_usd(budget))
        }
        BudgetOwner::Personal => format!("{} / {}", format_usd(spend), format_usd(budget)),
    };
    let window = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        resets_at,
        Some(BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Some(window))
}

fn cost_summary(
    spend: Decimal,
    budget: Option<Decimal>,
    resets_at: Option<Timestamp>,
    owner: &str,
    fetched_at: Timestamp,
) -> Result<Option<CostSummary>, ClassifiedError> {
    let limit = budget.unwrap_or(Decimal::ZERO).max(Decimal::ZERO);
    if spend <= Decimal::ZERO && limit <= Decimal::ZERO {
        return Ok(None);
    }
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    CostSummary::new(
        CostAmount::money(ExactDecimal::new(spend), currency),
        ExactDecimal::new(limit),
        Some(format!(
            "{owner} {}",
            if limit > Decimal::ZERO {
                "budget"
            } else {
                "spend"
            }
        )),
        resets_at,
        None,
        None,
        None,
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn clean_identifier(value: Option<String>) -> Result<Option<String>, ClassifiedError> {
    let value = value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    });
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_IDENTIFIER_BYTES || value.contains(char::is_control))
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(value)
}

fn first_non_empty<const N: usize>(values: [Option<&str>; N]) -> Option<String> {
    values.into_iter().find_map(clean_optional_text)
}

fn clean_optional_text(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn parse_optional_timestamp(value: Option<&str>) -> Option<Timestamp> {
    value.and_then(|value| Timestamp::parse(value).ok())
}

fn format_usd(value: Decimal) -> String {
    let raw = format!("{value:.2}");
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw.as_str(), "00"));
    let (sign, digits) = whole
        .strip_prefix('-')
        .map_or(("", whole), |digits| ("-", digits));
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3 + 1);
    grouped.push('$');
    grouped.push_str(sign);
    for (index, byte) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    grouped.push('.');
    grouped.push_str(fraction);
    grouped
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
