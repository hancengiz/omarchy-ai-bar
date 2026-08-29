//! ai& 30-day spend aggregation from bounded request-log pagination.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, CostAmount, CostProvenance, CostSummary, CurrencyCode,
    DataConfidence, ErrorKind, ExactDecimal, ProviderId, Timestamp, UsageSample,
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

const API_ORIGIN: &str = "https://api.aiand.com/";
const KEY_NAMES: [&str; 1] = ["AIAND_API_KEY"];
const PAGE_LIMIT: usize = 100;
const MAX_PAGES: usize = 10;
const MAX_CURSOR_BYTES: usize = 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const LOOKBACK_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Native ai& provider adapter.
pub struct AiAndProvider {
    client: FixedApiClient,
}

impl AiAndProvider {
    /// Resolves the API key from the pinned baseline environment name.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when the key is unusable.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &KEY_NAMES)
    }

    /// Creates the production fixed-origin client.
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
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::AiAnd {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
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
        let mut after: Option<String> = None;
        let mut after_id: Option<String> = None;
        let mut summary = SpendSummary::default();
        let mut is_complete = false;

        for _ in 0..MAX_PAGES {
            let url = logs_url(
                self.client.base_url(),
                after.as_deref(),
                after_id.as_deref(),
            )?;
            let page: LogsEnvelope = self.client.get_json(context, url).await?.json()?;
            summary.add_rows(page.data)?;
            if !page.has_more.unwrap_or(false) {
                is_complete = true;
                break;
            }
            let (Some(next_after), Some(next_after_id)) = (page.next_after, page.next_after_id)
            else {
                break;
            };
            validate_cursor(&next_after)?;
            validate_cursor(&next_after_id)?;
            after = Some(next_after);
            after_id = Some(next_after_id);
        }

        normalize(context.scope().clone(), fetched_at, summary, is_complete)
    }
}

impl ProviderAdapter for AiAndProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::AiAnd)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct LogsEnvelope {
    data: Vec<LogRow>,
    has_more: Option<bool>,
    next_after: Option<String>,
    next_after_id: Option<String>,
}

#[derive(Deserialize)]
struct LogRow {
    cost: Option<String>,
    currency: Option<String>,
}

#[derive(Default)]
struct SpendSummary {
    currency: Option<String>,
    total: Decimal,
}

impl SpendSummary {
    fn add_rows(&mut self, rows: Vec<LogRow>) -> Result<(), ClassifiedError> {
        for row in rows {
            let (Some(raw_cost), Some(raw_currency)) = (row.cost, row.currency) else {
                continue;
            };
            let Ok(cost) = raw_cost.parse::<Decimal>() else {
                continue;
            };
            let currency = raw_currency.trim().to_ascii_lowercase();
            if currency.is_empty() {
                continue;
            }
            if self.currency.is_none() {
                self.currency = Some(currency.clone());
            }
            if self.currency.as_deref() != Some(currency.as_str()) {
                continue;
            }
            self.total = self
                .total
                .checked_add(cost)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        }
        Ok(())
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    summary: SpendSummary,
    is_complete: bool,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at).confidence(if is_complete {
        DataConfidence::Exact
    } else {
        DataConfidence::Estimated
    });
    if let Some(currency) = summary.currency {
        let currency =
            CurrencyCode::new(currency).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let period_start_seconds = fetched_at
            .unix_timestamp()
            .checked_sub(LOOKBACK_SECONDS)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let period_start = timestamp_from_unix(period_start_seconds)?;
        let period = if is_complete {
            "Last 30 days"
        } else {
            "Last 30 days (partial)"
        };
        let cost = CostSummary::new(
            CostAmount::money(ExactDecimal::new(summary.total), currency),
            ExactDecimal::new(Decimal::ZERO),
            Some(period.to_owned()),
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
    builder.provenance("aiand", "api")?.build()
}

fn logs_url(
    base_url: &Url,
    after: Option<&str>,
    after_id: Option<&str>,
) -> Result<Url, ClassifiedError> {
    if after.is_some() != after_id.is_some() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let mut url = base_url
        .join("logs")
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let mut query = format!("range=30days&limit={PAGE_LIMIT}");
    if let (Some(after), Some(after_id)) = (after, after_id) {
        query.push_str("&after=");
        query.push_str(&encode_query_component(after));
        query.push_str("&after_id=");
        query.push_str(&encode_query_component(after_id));
    }
    url.set_query(Some(&query));
    Ok(url)
}

fn encode_query_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn validate_cursor(cursor: &str) -> Result<(), ClassifiedError> {
    if cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control)
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
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
