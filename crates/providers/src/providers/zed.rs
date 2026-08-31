//! `Zed` cloud account and edit-prediction usage adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, NamedRateWindow, ProviderId, RateWindow,
    Timestamp, UsagePercent, UsageSample, WindowUsage,
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

const API_ORIGIN: &str = "https://cloud.zed.dev";
const USER_ID_ENV: &str = "ZED_USER_ID";
const ACCESS_TOKEN_ENV: &str = "ZED_ACCESS_TOKEN";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Explicit Linux-compatible Zed credentials.
pub struct ZedSettings {
    user_id: String,
    access_token: ApiKeyCredential,
}

impl ZedSettings {
    /// Resolves the Zed user ID and access token from the environment.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when either value is absent.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let user_id = environment
            .get(USER_ID_ENV)
            .map(|value| value.trim().trim_matches(['\'', '"']))
            .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?
            .to_owned();
        let access_token = ApiKeyCredential::resolve(environment, &[ACCESS_TOKEN_ENV])?;
        Ok(Self {
            user_id,
            access_token,
        })
    }
}

impl Debug for ZedSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZedSettings")
            .field("user_id", &"<redacted>")
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// Native `Zed` provider adapter.
pub struct ZedProvider {
    client: FixedApiClient,
}

impl ZedProvider {
    /// Creates the fixed-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid credentials or transport configuration.
    pub fn new(scope: AccountScope, settings: ZedSettings) -> Result<Self, ClassifiedError> {
        let base = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_authorization_scheme(
            scope,
            base,
            EndpointClass::PublicHttps,
            settings.user_id,
            settings.access_token,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Binds a validated client for deterministic loopback tests.
    #[doc(hidden)]
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Zed {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches the authenticated Zed account and usage state.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("client/users/me")?;
        let payload: AccountResponse = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, payload)
    }
}

impl ProviderAdapter for ZedProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Zed)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct AccountResponse {
    user: User,
    plan: Plan,
}

#[derive(Deserialize)]
struct User {
    id: i64,
    github_login: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Plan {
    #[serde(rename = "plan_v3")]
    kind: String,
    subscription_period: Option<SubscriptionPeriod>,
    usage: CurrentUsage,
    #[serde(default)]
    has_overdue_invoices: bool,
}

#[derive(Deserialize)]
struct SubscriptionPeriod {
    started_at: Timestamp,
    ended_at: Timestamp,
}

#[derive(Deserialize)]
struct CurrentUsage {
    edit_predictions: EditPredictions,
}

#[derive(Deserialize)]
struct EditPredictions {
    used: i64,
    limit: UsageLimit,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum UsageLimit {
    Limited(i64),
    Object { limited: i64 },
    Text(String),
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: AccountResponse,
) -> Result<UsageSample, ClassifiedError> {
    let primary = prediction_window(payload.plan.usage.edit_predictions)?;
    let secondary = payload
        .plan
        .subscription_period
        .as_ref()
        .map(|period| billing_window(fetched_at, period))
        .transpose()?;
    let mut extra_windows = Vec::new();
    if payload.plan.has_overdue_invoices {
        let warning = RateWindow::new(
            WindowUsage::unknown(),
            None,
            None,
            Some(BoundedText::new("Overdue invoices").map_err(|_| parse_error())?),
            None,
            false,
        )
        .map_err(|_| parse_error())?;
        extra_windows.push(NamedRateWindow::new(
            BoundedText::new("zed.overdue-invoices").map_err(|_| parse_error())?,
            BoundedText::new("Billing").map_err(|_| parse_error())?,
            warning,
        ));
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .extra_windows(extra_windows)
        .provider_account_id(Some(payload.user.id.to_string()))?
        .email(non_empty(payload.user.github_login))?
        .organization(payload.user.name.and_then(non_empty))?
        .login_method(Some(display_plan_name(&payload.plan.kind)))?
        .subscription_renews_at(
            payload
                .plan
                .subscription_period
                .as_ref()
                .map(|period| period.ended_at),
        );
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("zed", "cloud-api")?.build()
}

fn prediction_window(usage: EditPredictions) -> Result<RateWindow, ClassifiedError> {
    let (percent, description) = match usage.limit {
        UsageLimit::Limited(limit) | UsageLimit::Object { limited: limit } if limit > 0 => {
            let used = usage.used.clamp(0, limit);
            (
                ratio_percent(used, limit)?,
                format!("{used} / {limit} predictions"),
            )
        }
        UsageLimit::Text(value) if value.eq_ignore_ascii_case("unlimited") => {
            (0.0, "Unlimited".to_owned())
        }
        _ => return Err(parse_error()),
    };
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        None,
        None,
        Some(BoundedText::new(description).map_err(|_| parse_error())?),
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn billing_window(
    fetched_at: Timestamp,
    period: &SubscriptionPeriod,
) -> Result<RateWindow, ClassifiedError> {
    let start = period.started_at.unix_timestamp();
    let end = period.ended_at.unix_timestamp();
    if end <= start {
        return Err(parse_error());
    }
    let elapsed = fetched_at.unix_timestamp().saturating_sub(start);
    let percent = ratio_percent(elapsed, end - start)?.clamp(0.0, 100.0);
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        None,
        Some(period.ended_at),
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn display_plan_name(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn ratio_percent(numerator: i64, denominator: i64) -> Result<f64, ClassifiedError> {
    if denominator <= 0 {
        return Err(parse_error());
    }
    (Decimal::from(numerator) * Decimal::ONE_HUNDRED / Decimal::from(denominator))
        .to_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(parse_error)
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
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
