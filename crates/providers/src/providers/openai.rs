//! `OpenAI` Admin API usage and legacy credit-balance fallback.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary, CostUnit,
    CostUsageCoverage, CostUsageDailyBucket, CostUsageInterval, CostUsageLineItem,
    CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot, CostUsageTokenMix, CurrencyCode,
    ErrorKind, ExactDecimal, Money, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp, timestamp_from_unix};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.openai.com";
const ADMIN_KEY: &str = "OPENAI_ADMIN_KEY";
const API_KEY: &str = "OPENAI_API_KEY";
const PROJECT_ID: &str = "OPENAI_PROJECT_ID";
const COSTS_PATH: &str = "v1/organization/costs";
const COMPLETIONS_PATH: &str = "v1/organization/usage/completions";
const CREDIT_GRANTS_PATH: &str = "v1/dashboard/billing/credit_grants";
const MAX_DAILY_BUCKET_LIMIT: u16 = 31;
const MAX_PAGINATION_PAGES: usize = 100;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 2048;
const MAX_PROJECT_ID_BYTES: usize = 160;
const SECONDS_PER_DAY: i64 = 86_400;

/// One selected `OpenAI` secret and its non-secret scope metadata.
pub struct OpenAiCredential {
    key: ApiKeyCredential,
    uses_admin_key: bool,
    project_id: Option<String>,
}

impl OpenAiCredential {
    /// Resolves `OPENAI_ADMIN_KEY` before `OPENAI_API_KEY` and reads the
    /// optional project filter.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let uses_admin_key = environment
            .get(ADMIN_KEY)
            .and_then(|value| clean_setting(value))
            .is_some();
        let key = if uses_admin_key {
            ApiKeyCredential::resolve(environment, &[ADMIN_KEY])?
        } else {
            ApiKeyCredential::resolve(environment, &[API_KEY])?
        };
        let project_id = environment
            .get(PROJECT_ID)
            .map(String::as_str)
            .and_then(clean_setting)
            .map(validate_project_id)
            .transpose()?;
        Ok(Self {
            key,
            uses_admin_key,
            project_id,
        })
    }

    /// Builds an explicitly selected credential for non-environment callers.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error for an invalid project identifier.
    pub fn new(
        key: ApiKeyCredential,
        uses_admin_key: bool,
        project_id: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let project_id = project_id
            .and_then(clean_setting)
            .map(validate_project_id)
            .transpose()?;
        Ok(Self {
            key,
            uses_admin_key,
            project_id,
        })
    }
}

impl Debug for OpenAiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiCredential")
            .field("key", &"<redacted>")
            .field("uses_admin_key", &self.uses_admin_key)
            .field(
                "project_id",
                &self.project_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Native `OpenAI` provider adapter.
pub struct OpenAiProvider {
    client: FixedApiClient,
    uses_admin_key: bool,
    project_id: Option<String>,
    history_days: u16,
}

impl OpenAiProvider {
    /// Creates the production fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(
        scope: AccountScope,
        credential: OpenAiCredential,
        history_days: u16,
    ) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            credential.key,
            transport_config()?,
        )?;
        Self::from_client(
            client,
            credential.uses_admin_key,
            credential.project_id,
            history_days,
        )
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// This seam supports deterministic loopback fixtures without weakening
    /// the production constructor's fixed HTTPS origin.
    ///
    /// # Errors
    ///
    /// Returns a stable API or parse error for another provider or an invalid
    /// project identifier.
    pub fn from_client(
        client: FixedApiClient,
        uses_admin_key: bool,
        project_id: Option<String>,
        history_days: u16,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::OpenAi {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let project_id = project_id.map(validate_project_id).transpose()?;
        Ok(Self {
            client,
            uses_admin_key,
            project_id,
            history_days: history_days.clamp(1, 365),
        })
    }

    /// Fetches one deterministic sample timestamp.
    ///
    /// Admin usage is preferred. A project-scoped Admin credential never
    /// falls back to the unscoped credit endpoint.
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
        let admin = self.fetch_admin(context, fetched_at).await;
        match admin {
            Ok(sample) => Ok(sample),
            Err(admin_error) if self.uses_admin_key && self.project_id.is_some() => {
                Err(admin_error)
            }
            Err(admin_error) => match self.fetch_credits(context, fetched_at).await {
                Ok(sample) => Ok(sample),
                Err(fallback_error)
                    if matches!(
                        admin_error.kind(),
                        ErrorKind::AuthenticationExpired | ErrorKind::PermissionDenied
                    ) =>
                {
                    Err(fallback_error)
                }
                Err(_) => Err(admin_error),
            },
        }
    }

    async fn fetch_admin(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let ranges = daily_ranges(fetched_at, self.history_days)?;
        let costs = self
            .fetch_pages::<CostBucket>(context, COSTS_PATH, "line_item", &ranges)
            .await?;
        let completions = self
            .fetch_pages::<CompletionBucket>(context, COMPLETIONS_PATH, "model", &ranges)
            .await?;
        normalize_admin(
            context.scope().clone(),
            fetched_at,
            self.history_days,
            self.project_id.as_deref(),
            &ranges,
            costs,
            completions,
        )
    }

    async fn fetch_pages<T: DeserializeOwned>(
        &self,
        context: &ProviderContext,
        path: &str,
        group_by: &str,
        ranges: &[DateRange],
    ) -> Result<Vec<T>, ClassifiedError> {
        let mut buckets = Vec::new();
        for range in ranges {
            let mut next_page: Option<String> = None;
            let mut seen_pages = BTreeSet::new();
            for page_index in 0..MAX_PAGINATION_PAGES {
                let url = self.request_url(path, group_by, *range, next_page.as_deref())?;
                let response = self.client.get(context, url).await?;
                let page: Page<T> = serde_json::from_slice(response.body())
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
                buckets.extend(page.data);
                if !page.has_more {
                    next_page = None;
                    break;
                }
                let cursor = page
                    .next_cursor
                    .as_deref()
                    .and_then(clean_setting)
                    .filter(|value| value.len() <= MAX_CURSOR_BYTES)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                if !seen_pages.insert(cursor.to_owned()) {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                next_page = Some(cursor.to_owned());
                if page_index + 1 == MAX_PAGINATION_PAGES {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
            }
            if next_page.is_some() {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
        }
        Ok(buckets)
    }

    fn request_url(
        &self,
        path: &str,
        group_by: &str,
        range: DateRange,
        page: Option<&str>,
    ) -> Result<Url, ClassifiedError> {
        let mut url = self.client.url(path)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("start_time", &range.start.to_string());
            query.append_pair("end_time", &range.end.to_string());
            query.append_pair("bucket_width", "1d");
            query.append_pair("limit", &range.days.to_string());
            query.append_pair("group_by", group_by);
            if let Some(project_id) = &self.project_id {
                query.append_pair("project_ids", project_id);
            }
            if let Some(page) = page {
                query.append_pair("page", page);
            }
        }
        Ok(url)
    }

    async fn fetch_credits(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url(CREDIT_GRANTS_PATH)?;
        let response = self.client.get(context, url).await?;
        let credits: CreditResponse = serde_json::from_slice(response.body())
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        normalize_credits(context.scope().clone(), fetched_at, credits)
    }
}

impl ProviderAdapter for OpenAiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::OpenAi)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for OpenAiProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiProvider")
            .field("client", &self.client)
            .field("uses_admin_key", &self.uses_admin_key)
            .field(
                "project_id",
                &self.project_id.as_ref().map(|_| "<redacted>"),
            )
            .field("history_days", &self.history_days)
            .finish()
    }
}

#[derive(Clone, Copy)]
struct DateRange {
    start: i64,
    end: i64,
    days: u16,
}

#[derive(Deserialize)]
struct Page<T> {
    data: Vec<T>,
    has_more: bool,
    #[serde(rename = "next_page")]
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct CostBucket {
    start_time: i64,
    end_time: i64,
    results: Vec<CostResult>,
}

#[derive(Deserialize)]
struct CostResult {
    amount: Option<CostValue>,
    line_item: Option<String>,
}

#[derive(Deserialize)]
struct CostValue {
    value: Option<FlexibleDecimal>,
    currency: Option<String>,
}

#[derive(Deserialize)]
struct CompletionBucket {
    start_time: i64,
    end_time: i64,
    results: Vec<CompletionResult>,
}

#[derive(Deserialize)]
struct CompletionResult {
    input_tokens: Option<i64>,
    input_cached_tokens: Option<i64>,
    input_audio_tokens: Option<i64>,
    output_tokens: Option<i64>,
    output_audio_tokens: Option<i64>,
    num_model_requests: Option<i64>,
    model: Option<String>,
}

#[derive(Deserialize)]
struct CreditResponse {
    total_granted: FlexibleDecimal,
    total_used: FlexibleDecimal,
    total_available: FlexibleDecimal,
    grants: Option<CreditGrantList>,
}

#[derive(Deserialize)]
struct CreditGrantList {
    data: Vec<CreditGrant>,
}

#[derive(Deserialize)]
struct CreditGrant {
    #[serde(rename = "grant_amount")]
    _grant_amount: Option<FlexibleDecimal>,
    #[serde(rename = "used_amount")]
    _used_amount: Option<FlexibleDecimal>,
    expires_at: Option<i64>,
}

#[derive(Clone, Copy)]
struct FlexibleDecimal(Decimal);

impl<'de> Deserialize<'de> for FlexibleDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Number(serde_json::Number),
            String(String),
        }

        let raw = match Repr::deserialize(deserializer)? {
            Repr::Number(value) => value.to_string(),
            Repr::String(value) => value.trim().to_owned(),
        };
        if raw.is_empty() {
            return Err(serde::de::Error::custom("empty decimal"));
        }
        Decimal::from_scientific(&raw)
            .or_else(|_| raw.parse())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

#[derive(Default)]
struct DailyAccumulator {
    start: i64,
    end: i64,
    cost: Decimal,
    requests: u64,
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    line_items: BTreeMap<String, Decimal>,
    models: BTreeMap<String, ModelAccumulator>,
}

impl DailyAccumulator {
    const fn new(start: i64, end: i64) -> Self {
        Self {
            start,
            end,
            cost: Decimal::ZERO,
            requests: 0,
            input_tokens: 0,
            cached_input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            line_items: BTreeMap::new(),
            models: BTreeMap::new(),
        }
    }

    fn metrics(&self) -> Result<CostUsageMetrics, ClassifiedError> {
        usage_metrics(
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.total_tokens,
            self.requests,
            Some(self.cost),
            true,
        )
    }

    fn add_completion(&mut self, result: &CompletionResult) -> Result<(), ClassifiedError> {
        let input = nonnegative(result.input_tokens)?;
        let cached = nonnegative(result.input_cached_tokens)?;
        let output = nonnegative(result.output_tokens)?;
        let audio_input = nonnegative(result.input_audio_tokens)?;
        let audio_output = nonnegative(result.output_audio_tokens)?;
        let requests = nonnegative(result.num_model_requests)?;
        let input = checked_sum(input, audio_input)?;
        let output = checked_sum(output, audio_output)?;
        let total = checked_sum(input, output)?;
        self.requests = checked_sum(self.requests, requests)?;
        self.input_tokens = checked_sum(self.input_tokens, input)?;
        self.cached_input_tokens = checked_sum(self.cached_input_tokens, cached)?;
        self.output_tokens = checked_sum(self.output_tokens, output)?;
        self.total_tokens = checked_sum(self.total_tokens, total)?;
        let model = display_name(result.model.as_deref(), "Responses and Chat Completions")?;
        self.models
            .entry(model)
            .or_default()
            .add(requests, input, cached, output, total)
    }

    fn into_bucket(self) -> Result<CostUsageDailyBucket, ClassifiedError> {
        let start = timestamp_from_unix(self.start)?;
        let end = timestamp_from_unix(self.end)?;
        let day = start
            .to_string()
            .get(..10)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .to_owned();
        let interval = CostUsageInterval::new(start, end).map_err(parse_error)?;
        let models_used = self.models.keys().cloned().collect();
        let models = self
            .models
            .into_iter()
            .map(|(name, model)| model.into_breakdown(name))
            .collect::<Result<Vec<_>, _>>()?;
        let line_items = self
            .line_items
            .into_iter()
            .map(|(name, amount)| {
                CostUsageLineItem::new(name, ExactDecimal::new(amount)).map_err(parse_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let metrics = usage_metrics(
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.total_tokens,
            self.requests,
            Some(self.cost),
            true,
        )?;
        CostUsageDailyBucket::new(
            day,
            Some(interval),
            metrics,
            models_used,
            models,
            line_items,
        )
        .map_err(parse_error)
    }
}

#[derive(Default)]
struct ModelAccumulator {
    requests: u64,
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

impl ModelAccumulator {
    fn add(
        &mut self,
        requests: u64,
        input: u64,
        cached: u64,
        output: u64,
        total: u64,
    ) -> Result<(), ClassifiedError> {
        self.requests = checked_sum(self.requests, requests)?;
        self.input_tokens = checked_sum(self.input_tokens, input)?;
        self.cached_input_tokens = checked_sum(self.cached_input_tokens, cached)?;
        self.output_tokens = checked_sum(self.output_tokens, output)?;
        self.total_tokens = checked_sum(self.total_tokens, total)?;
        Ok(())
    }

    fn into_breakdown(self, name: String) -> Result<CostUsageModelBreakdown, ClassifiedError> {
        let metrics = usage_metrics(
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.total_tokens,
            self.requests,
            None,
            false,
        )?;
        CostUsageModelBreakdown::new(name, metrics, None, None, None, None).map_err(parse_error)
    }
}

fn normalize_admin(
    scope: AccountScope,
    fetched_at: Timestamp,
    history_days: u16,
    project_id: Option<&str>,
    ranges: &[DateRange],
    costs: Vec<CostBucket>,
    completions: Vec<CompletionBucket>,
) -> Result<UsageSample, ClassifiedError> {
    let mut daily = BTreeMap::<i64, DailyAccumulator>::new();
    for bucket in costs {
        let accumulator = accumulator(&mut daily, bucket.start_time, bucket.end_time)?;
        for result in bucket.results {
            let Some(amount) = result.amount else {
                continue;
            };
            if amount
                .currency
                .as_deref()
                .is_some_and(|currency| !currency.eq_ignore_ascii_case("usd"))
            {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            let value = amount.value.map_or(Decimal::ZERO, |value| value.0);
            if value.is_sign_negative() {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            accumulator.cost = checked_decimal_sum(accumulator.cost, value)?;
            let line_item = display_name(result.line_item.as_deref(), "API")?;
            let line_total = accumulator.line_items.entry(line_item).or_default();
            *line_total = checked_decimal_sum(*line_total, value)?;
        }
    }
    for bucket in completions {
        let accumulator = accumulator(&mut daily, bucket.start_time, bucket.end_time)?;
        for result in bucket.results {
            accumulator.add_completion(&result)?;
        }
    }
    daily.retain(|start, _| *start <= fetched_at.unix_timestamp());

    let mut total = DailyAccumulator::default();
    let mut current = DailyAccumulator::default();
    for value in daily.values() {
        add_day(&mut total, value)?;
        if value.start <= fetched_at.unix_timestamp() && fetched_at.unix_timestamp() < value.end {
            add_day(&mut current, value)?;
        }
    }
    let history_metrics = total.metrics()?;
    let session_metrics = current.metrics()?;
    let metered_amount = ExactDecimal::new(total.cost);
    let daily = daily
        .into_values()
        .map(DailyAccumulator::into_bucket)
        .collect::<Result<Vec<_>, _>>()?;
    let currency = usd()?;
    let period_start = ranges
        .first()
        .map(|range| timestamp_from_unix(range.start))
        .transpose()?;
    let period_end = ranges
        .last()
        .map(|range| timestamp_from_unix(range.end))
        .transpose()?;
    let cost = CostSummary::new(
        CostAmount::money(metered_amount, currency.clone()),
        ExactDecimal::new(Decimal::ZERO),
        Some(history_period(history_days)),
        None,
        None,
        None,
        None,
        fetched_at,
        period_start,
        period_end,
        CostProvenance::VendorMetered,
    )
    .map_err(parse_error)?;
    let cost_usage = CostUsageSnapshot::new(
        CostUnit::currency(currency),
        session_metrics,
        history_metrics,
        Some(metered_amount),
        history_days,
        true,
        Some(history_label(history_days)),
        None,
        daily,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        fetched_at,
        CostProvenance::VendorMetered,
    )
    .map_err(parse_error)?;
    let login = project_id.map_or_else(
        || "Admin API".to_owned(),
        |project| format!("Admin API: {project}"),
    );
    let organization = project_id.map(|project| format!("Project: {project}"));
    UsageSampleBuilder::new(scope, fetched_at)
        .organization(organization)?
        .login_method(Some(login))?
        .cost(cost)
        .cost_usage(cost_usage)
        .provenance("openai", "admin-api")?
        .build()
}

fn normalize_credits(
    scope: AccountScope,
    fetched_at: Timestamp,
    credits: CreditResponse,
) -> Result<UsageSample, ClassifiedError> {
    let granted = credits.total_granted.0.max(Decimal::ZERO);
    let used = credits.total_used.0.max(Decimal::ZERO);
    let available = credits.total_available.0.max(Decimal::ZERO);
    let resets_at = credits
        .grants
        .into_iter()
        .flat_map(|grants| grants.data)
        .filter_map(|grant| grant.expires_at)
        .filter(|expires| *expires > fetched_at.unix_timestamp())
        .map(timestamp_from_unix)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min();
    let used_percent = if granted > Decimal::ZERO {
        (used * Decimal::from(100_u8) / granted)
            .to_f64()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .clamp(0.0, 100.0)
    } else if available > Decimal::ZERO {
        0.0
    } else {
        100.0
    };
    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(used_percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        resets_at,
        Some(
            BoundedText::new(format!("{} available", format_usd(available)))
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        false,
    )
    .map_err(parse_error)?;
    let currency = usd()?;
    let granted = ExactDecimal::new(granted);
    let used = ExactDecimal::new(used);
    let available = ExactDecimal::new(available);
    let balance = Money::new(available, currency.clone());
    let cost = CostSummary::new(
        CostAmount::money(used, currency),
        granted,
        Some("API credits".to_owned()),
        resets_at,
        None,
        None,
        Some(available),
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(parse_error)?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .balance(balance)
        .cost(cost)
        .login_method(Some(format!(
            "API balance: {}",
            format_usd(available.get())
        )))?
        .provenance("openai", "credit-grants")?
        .build()
}

fn accumulator(
    daily: &mut BTreeMap<i64, DailyAccumulator>,
    start: i64,
    end: i64,
) -> Result<&mut DailyAccumulator, ClassifiedError> {
    if end <= start {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let value = daily
        .entry(start)
        .or_insert_with(|| DailyAccumulator::new(start, end));
    if value.end != end {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(value)
}

fn add_day(target: &mut DailyAccumulator, value: &DailyAccumulator) -> Result<(), ClassifiedError> {
    target.cost = checked_decimal_sum(target.cost, value.cost)?;
    target.requests = checked_sum(target.requests, value.requests)?;
    target.input_tokens = checked_sum(target.input_tokens, value.input_tokens)?;
    target.cached_input_tokens =
        checked_sum(target.cached_input_tokens, value.cached_input_tokens)?;
    target.output_tokens = checked_sum(target.output_tokens, value.output_tokens)?;
    target.total_tokens = checked_sum(target.total_tokens, value.total_tokens)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn usage_metrics(
    input: u64,
    cached: u64,
    output: u64,
    total: u64,
    requests: u64,
    amount: Option<Decimal>,
    priced: bool,
) -> Result<CostUsageMetrics, ClassifiedError> {
    let coverage = if priced {
        CostUsageCoverage::new(requests, 0, 0, 0)
    } else {
        CostUsageCoverage::new(0, 0, requests, 0)
    }
    .map_err(parse_error)?;
    CostUsageMetrics::new(
        CostUsageTokenMix::new(Some(input), Some(output), Some(cached), None, None),
        Some(total),
        Some(requests),
        amount.map(ExactDecimal::new),
        coverage,
    )
    .map_err(parse_error)
}

fn daily_ranges(
    fetched_at: Timestamp,
    history_days: u16,
) -> Result<Vec<DateRange>, ClassifiedError> {
    let today = fetched_at.unix_timestamp().div_euclid(SECONDS_PER_DAY) * SECONDS_PER_DAY;
    let history_days = history_days.clamp(1, 365);
    let first_day = today
        .checked_sub(i64::from(history_days - 1) * SECONDS_PER_DAY)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut cursor = first_day;
    let mut remaining = history_days;
    let mut ranges = Vec::new();
    while remaining > 0 {
        let days = remaining.min(MAX_DAILY_BUCKET_LIMIT);
        let end = cursor
            .checked_add(i64::from(days) * SECONDS_PER_DAY)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        ranges.push(DateRange {
            start: cursor,
            end,
            days,
        });
        cursor = end;
        remaining -= days;
    }
    Ok(ranges)
}

fn nonnegative(value: Option<i64>) -> Result<u64, ClassifiedError> {
    value
        .unwrap_or(0)
        .try_into()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn checked_sum(left: u64, right: u64) -> Result<u64, ClassifiedError> {
    left.checked_add(right)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn checked_decimal_sum(left: Decimal, right: Decimal) -> Result<Decimal, ClassifiedError> {
    left.checked_add(right)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn display_name(value: Option<&str>, fallback: &str) -> Result<String, ClassifiedError> {
    let value = value.and_then(clean_setting).unwrap_or(fallback);
    BoundedText::<160>::new(value)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn validate_project_id(value: impl AsRef<str>) -> Result<String, ClassifiedError> {
    let value = value.as_ref();
    if value.len() > MAX_PROJECT_ID_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    BoundedText::<MAX_PROJECT_ID_BYTES>::new(value)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
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

fn history_label(days: u16) -> String {
    if days == 1 {
        "Today".to_owned()
    } else {
        format!("{days}d")
    }
}

fn history_period(days: u16) -> String {
    if days == 1 {
        "Today".to_owned()
    } else {
        format!("Last {days} days")
    }
}

fn format_usd(value: Decimal) -> String {
    format!("${:.2}", value.round_dp(2))
}

fn usd() -> Result<CurrencyCode, ClassifiedError> {
    CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn parse_error<T>(_error: T) -> ClassifiedError {
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
