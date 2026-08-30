//! Fireworks 30-day billing summary with bounded account discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, ProviderId, Timestamp, UsageSample,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp, timestamp_from_unix};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.fireworks.ai";
const API_KEY_NAMES: [&str; 2] = ["FIREWORKS_API_KEY", "FIREWORKS_KEY"];
const ACCOUNT_SLUG_NAMES: [&str; 1] = ["FIREWORKS_ACCOUNT_SLUG"];
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACCOUNT_SLUG_BYTES: usize = 160;
const MAX_PAGE_TOKEN_BYTES: usize = 2048;
const MAX_ACCOUNT_PAGES: usize = 100;
const LOOKBACK_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Selected Fireworks API key and optional account slug.
pub struct FireworksCredential {
    key: ApiKeyCredential,
    account_slug: Option<String>,
}

impl FireworksCredential {
    /// Resolves the standard Fireworks key and account-slug precedence.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or invalid-configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let key = ApiKeyCredential::resolve(environment, &API_KEY_NAMES)?;
        let account_slug = ACCOUNT_SLUG_NAMES
            .iter()
            .filter_map(|name| environment.get(*name))
            .find_map(|value| clean_setting(value))
            .map(validate_account_slug)
            .transpose()?;
        Ok(Self { key, account_slug })
    }

    /// Builds an explicitly selected key and account slug.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an unsafe account slug.
    pub fn new(key: ApiKeyCredential, account_slug: Option<&str>) -> Result<Self, ClassifiedError> {
        let account_slug = account_slug
            .and_then(clean_setting)
            .map(validate_account_slug)
            .transpose()?;
        Ok(Self { key, account_slug })
    }
}

impl Debug for FireworksCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FireworksCredential")
            .field("key", &"<redacted>")
            .field(
                "account_slug",
                &self.account_slug.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Native Fireworks provider adapter.
pub struct FireworksProvider {
    client: FixedApiClient,
    account_slug: Option<String>,
}

impl FireworksProvider {
    /// Creates the production fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(
        scope: AccountScope,
        credential: FireworksCredential,
    ) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            credential.key,
            transport_config()?,
        )?;
        Self::from_client(client, credential.account_slug)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider or an unsafe slug.
    pub fn from_client(
        client: FixedApiClient,
        account_slug: Option<String>,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Fireworks {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let account_slug = account_slug.map(validate_account_slug).transpose()?;
        Ok(Self {
            client,
            account_slug,
        })
    }

    /// Fetches and normalizes one deterministic 30-day billing summary.
    ///
    /// # Errors
    ///
    /// Returns stable classified account, transport, or parse errors without
    /// provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let (summary, discovered) = if let Some(configured) = &self.account_slug {
            match self.fetch_summary(context, configured, fetched_at).await? {
                Some(summary) if summary.spend.is_some() => (summary, false),
                Some(summary) => {
                    let accounts = self.list_accounts(context).await?;
                    if !accounts.contains(configured) {
                        return Err(ClassifiedError::new(ErrorKind::Api));
                    }
                    (summary, false)
                }
                None => {
                    let accounts = self.list_accounts(context).await?;
                    let discovered = single_account(&accounts)?;
                    let summary = self
                        .fetch_summary(context, discovered, fetched_at)
                        .await?
                        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
                    (summary, discovered != configured)
                }
            }
        } else {
            let accounts = self.list_accounts(context).await?;
            let discovered = single_account(&accounts)?;
            let summary = self
                .fetch_summary(context, discovered, fetched_at)
                .await?
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
            (summary, true)
        };
        normalize(context.scope().clone(), fetched_at, summary, discovered)
    }

    async fn fetch_summary(
        &self,
        context: &ProviderContext,
        account_slug: &str,
        fetched_at: Timestamp,
    ) -> Result<Option<BillingSummary>, ClassifiedError> {
        let start = fetched_at
            .unix_timestamp()
            .checked_sub(LOOKBACK_SECONDS)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let mut url = self
            .client
            .url(&format!("v1/accounts/{account_slug}/billing/summary"))?;
        url.query_pairs_mut()
            .append_pair("startTime", &timestamp_from_unix(start)?.to_string())
            .append_pair("endTime", &fetched_at.to_string());
        let Some(response) = self.client.get_optional_json(context, url).await? else {
            return Ok(None);
        };
        response
            .json::<BillingSummaryResponse>()
            .and_then(parse_summary)
            .map(Some)
    }

    async fn list_accounts(
        &self,
        context: &ProviderContext,
    ) -> Result<BTreeSet<String>, ClassifiedError> {
        let mut accounts = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        let mut page_token: Option<String> = None;
        for page_index in 0..MAX_ACCOUNT_PAGES {
            let mut url = self.client.url("v1/accounts")?;
            if let Some(token) = &page_token {
                url.query_pairs_mut().append_pair("pageToken", token);
            }
            let page: AccountsResponse = self.client.get_json(context, url).await?.json()?;
            for account in page.accounts.unwrap_or_default() {
                if let Some(slug) = account
                    .slug()
                    .and_then(|slug| validate_account_slug(slug).ok())
                {
                    accounts.insert(slug);
                }
            }
            let Some(token) = page.next_page_token.as_deref().and_then(clean_setting) else {
                return Ok(accounts);
            };
            if token.len() > MAX_PAGE_TOKEN_BYTES || !seen_tokens.insert(token.to_owned()) {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            page_token = Some(token.to_owned());
            if page_index + 1 == MAX_ACCOUNT_PAGES {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
        }
        Err(ClassifiedError::new(ErrorKind::Parse))
    }
}

impl ProviderAdapter for FireworksProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Fireworks)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct BillingSummaryResponse {
    #[serde(rename = "lineItems")]
    line_items: Option<Vec<LineItem>>,
}

#[derive(Deserialize)]
struct LineItem {
    #[serde(rename = "totalCost")]
    total_cost: Option<FireworksMoney>,
}

#[derive(Deserialize)]
struct FireworksMoney {
    #[serde(rename = "currencyCode")]
    currency_code: Option<String>,
    nanos: Option<i64>,
    units: Option<String>,
}

#[derive(Deserialize)]
struct AccountsResponse {
    accounts: Option<Vec<FireworksAccount>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct FireworksAccount {
    name: Option<String>,
    #[serde(rename = "accountId")]
    account_id: Option<String>,
    id: Option<String>,
}

impl FireworksAccount {
    fn slug(&self) -> Option<&str> {
        [&self.account_id, &self.id, &self.name]
            .into_iter()
            .filter_map(Option::as_deref)
            .find_map(|value| clean_setting(value))
            .and_then(|value| value.rsplit('/').next())
    }
}

struct BillingSummary {
    spend: Option<ExactDecimal>,
    currency: Option<CurrencyCode>,
}

fn parse_summary(response: BillingSummaryResponse) -> Result<BillingSummary, ClassifiedError> {
    let mut selected_currency: Option<String> = None;
    let mut total = Decimal::ZERO;
    for item in response.line_items.unwrap_or_default() {
        let Some(cost) = item.total_cost else {
            continue;
        };
        let (Some(units), Some(nanos), Some(currency)) = (
            cost.units.as_deref(),
            cost.nanos,
            cost.currency_code.as_deref().and_then(clean_setting),
        ) else {
            continue;
        };
        let units = units
            .trim()
            .parse::<Decimal>()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        if selected_currency.is_none() {
            selected_currency = Some(currency.to_owned());
        }
        if selected_currency.as_deref() != Some(currency) {
            continue;
        }
        let nanos = Decimal::from(nanos) / Decimal::from(1_000_000_000_u64);
        total = total
            .checked_add(units)
            .and_then(|value| value.checked_add(nanos))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    }
    let currency = selected_currency
        .map(CurrencyCode::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(BillingSummary {
        spend: currency.as_ref().map(|_| ExactDecimal::new(total)),
        currency,
    })
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    summary: BillingSummary,
    discovered: bool,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let (Some(spend), Some(currency)) = (summary.spend, summary.currency) {
        let period_start = fetched_at
            .unix_timestamp()
            .checked_sub(LOOKBACK_SECONDS)
            .map(timestamp_from_unix)
            .transpose()?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let cost = CostSummary::new(
            CostAmount::money(spend, currency),
            ExactDecimal::new(Decimal::ZERO),
            Some("Last 30 days".to_owned()),
            None,
            None,
            None,
            None,
            fetched_at,
            Some(period_start),
            Some(fetched_at),
            CostProvenance::VendorMetered,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.cost(cost);
    }
    builder
        .provenance(
            "fireworks",
            if discovered {
                "api-auto-discovered"
            } else {
                "api"
            },
        )?
        .build()
}

fn single_account(accounts: &BTreeSet<String>) -> Result<&str, ClassifiedError> {
    if accounts.len() != 1 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    accounts
        .first()
        .map(String::as_str)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))
}

fn validate_account_slug(value: impl AsRef<str>) -> Result<String, ClassifiedError> {
    let value = value.as_ref();
    if value.is_empty()
        || value.len() > MAX_ACCOUNT_SLUG_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    BoundedText::<MAX_ACCOUNT_SLUG_BYTES>::new(value)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn clean_setting(raw: &str) -> Option<&str> {
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

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
