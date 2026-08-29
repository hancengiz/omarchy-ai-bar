//! Chutes subscription usage and best-effort quota enrichment.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{Map, Value};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "CHUTES_API_KEY";
const API_URL: &str = "CHUTES_API_URL";
const DEFAULT_API_URL: &str = "https://api.chutes.ai";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENRICHED_QUOTAS: usize = 64;
const MAX_QUOTA_IDENTIFIER_BYTES: usize = 200;
const MAX_NESTING_DEPTH: usize = 32;
const ROLLING_MINUTES: i64 = 4 * 60;
const MONTHLY_MINUTES: i64 = 30 * 24 * 60;

/// Validated Chutes endpoint and secret.
pub struct ChutesSettings {
    credential: ApiKeyCredential,
    endpoint: Url,
    endpoint_class: EndpointClass,
}

impl ChutesSettings {
    /// Resolves the baseline environment settings and HTTPS override.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential or API configuration errors.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let endpoint = match environment
            .get(API_URL)
            .and_then(|value| clean_setting(value))
        {
            Some(value) => normalize_https_endpoint(value)?,
            None => {
                Url::parse(DEFAULT_API_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            }
        };
        let endpoint_class =
            classify_https_endpoint(&endpoint).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self {
            credential,
            endpoint,
            endpoint_class,
        })
    }
}

impl Debug for ChutesSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChutesSettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .field("endpoint_class", &self.endpoint_class)
            .finish()
    }
}

/// Native Chutes provider adapter.
pub struct ChutesProvider {
    client: FixedApiClient,
}

impl ChutesProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: ChutesSettings) -> Result<Self, ClassifiedError> {
        let ChutesSettings {
            credential,
            endpoint,
            endpoint_class,
        } = settings;
        let client = FixedApiClient::new_bearer(
            scope,
            endpoint,
            endpoint_class,
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
        if client.scope().provider() != ProviderId::Chutes {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches subscription usage, then best-effort quota enrichment when a
    /// rolling or monthly lane is absent.
    ///
    /// # Errors
    ///
    /// Subscription failures and any authentication failure are authoritative.
    /// Other optional-quota failures preserve the subscription snapshot.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let subscription_url = append_segments(
            self.client.base_url(),
            &["users", "me", "subscription_usage"],
        )?;
        let subscription_value: Value = self
            .client
            .get_json(context, subscription_url)
            .await?
            .json()?;
        let subscription = parse_snapshot(&subscription_value);
        let snapshot = if subscription.rolling.is_some() && subscription.monthly.is_some() {
            subscription
        } else {
            match self.fetch_quotas(context).await {
                Ok(quotas) if quotas.has_usage() => quotas.with_subscription_context(subscription),
                Err(error) if is_authentication_error(&error) => return Err(error),
                Ok(_) | Err(_) => subscription,
            }
        };
        normalize(context.scope().clone(), fetched_at, &snapshot)
    }

    async fn fetch_quotas(
        &self,
        context: &ProviderContext,
    ) -> Result<ChutesSnapshot, ClassifiedError> {
        let quotas_url = append_segments(self.client.base_url(), &["users", "me", "quotas"])?;
        let quotas_value: Value = self.client.get_json(context, quotas_url).await?.json()?;
        let fallback = parse_snapshot(&quotas_value);
        let mut definitions = quota_definitions(&quotas_value);
        if definitions.is_empty() {
            return Ok(fallback);
        }
        definitions.truncate(MAX_ENRICHED_QUOTAS);
        let mut enriched = Vec::with_capacity(definitions.len());
        for definition in definitions {
            let Some(identifier) = quota_identifier(&definition) else {
                enriched.push(definition);
                continue;
            };
            let usage_url = append_segments(
                self.client.base_url(),
                &["users", "me", "quota_usage", &identifier],
            )?;
            match self.client.get_json(context, usage_url).await {
                Ok(response) => match response.json::<Value>() {
                    Ok(value) => {
                        let mut definition = definition;
                        if let Some(usage) = response_dictionary(&value) {
                            definition.extend(usage.clone());
                        }
                        enriched.push(definition);
                    }
                    Err(_) => enriched.push(definition),
                },
                Err(error) if is_authentication_error(&error) => return Err(error),
                Err(_) => enriched.push(definition),
            }
        }
        let value = Value::Object(Map::from_iter([(
            "quotas".to_owned(),
            Value::Array(enriched.into_iter().map(Value::Object).collect()),
        )]));
        let enriched = parse_snapshot(&value);
        Ok(if enriched.has_usage() {
            enriched
        } else {
            fallback
        })
    }
}

impl ProviderAdapter for ChutesProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Chutes)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionState {
    Active,
    Inactive,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
struct QuotaWindow {
    label: Option<String>,
    used: Option<f64>,
    limit: Option<f64>,
    remaining: Option<f64>,
    used_percent: Option<f64>,
    window_minutes: Option<i64>,
    resets_at: Option<Timestamp>,
    unit: Option<String>,
}

impl QuotaWindow {
    fn usage_percent(&self) -> Option<f64> {
        if let Some(percent) = self.used_percent {
            return Some(percent.clamp(0.0, 100.0));
        }
        let mut used = self.used;
        let mut limit = self.limit;
        let remaining = self.remaining;
        if limit.is_none()
            && let (Some(used), Some(remaining)) = (used, remaining)
        {
            limit = Some(used + remaining);
        }
        if used.is_none()
            && let (Some(limit), Some(remaining)) = (limit, remaining)
        {
            used = Some(limit - remaining);
        }
        let (Some(used), Some(limit)) = (used, limit) else {
            return None;
        };
        (limit > 0.0).then_some((used / limit) * 100.0)
    }

    fn rate_window(
        &self,
        default_minutes: Option<i64>,
    ) -> Result<Option<RateWindow>, ClassifiedError> {
        let Some(percent) = self.usage_percent() else {
            return Ok(None);
        };
        let duration = self
            .window_minutes
            .or(default_minutes)
            .filter(|minutes| *minutes > 0)
            .map(WindowDuration::from_provider_minutes)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let description = self
            .usage_description()
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let percent = UsagePercent::new(percent.clamp(0.0, 100.0))
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        RateWindow::new(
            WindowUsage::known(percent),
            duration,
            self.resets_at,
            description,
            None,
            false,
        )
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
    }

    fn usage_description(&self) -> Option<String> {
        let limit = self.limit.filter(|limit| *limit > 0.0)?;
        let used = self
            .used
            .or_else(|| self.remaining.map(|remaining| (limit - remaining).max(0.0)))?;
        let suffix = self
            .unit
            .as_deref()
            .map(str::trim)
            .filter(|unit| !unit.is_empty())
            .map_or_else(String::new, |unit| format!(" {unit}"));
        Some(format!(
            "{}/{}{}",
            format_amount(used),
            format_amount(limit),
            suffix
        ))
    }
}

#[derive(Clone)]
struct ChutesSnapshot {
    rolling: Option<QuotaWindow>,
    monthly: Option<QuotaWindow>,
    fallback: Vec<QuotaWindow>,
    subscription_state: SubscriptionState,
    plan_name: Option<String>,
    subscription_renews_at: Option<Timestamp>,
}

impl ChutesSnapshot {
    fn has_usage(&self) -> bool {
        self.rolling.is_some() || self.monthly.is_some() || !self.fallback.is_empty()
    }

    fn with_subscription_context(self, subscription: Self) -> Self {
        let mut fallback = subscription.fallback;
        fallback.extend(self.fallback);
        Self {
            rolling: subscription.rolling.or(self.rolling),
            monthly: subscription.monthly.or(self.monthly),
            fallback,
            subscription_state: subscription.subscription_state,
            plan_name: subscription.plan_name,
            subscription_renews_at: subscription.subscription_renews_at,
        }
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    snapshot: &ChutesSnapshot,
) -> Result<UsageSample, ClassifiedError> {
    let fallback = snapshot
        .fallback
        .iter()
        .filter_map(|window| window.rate_window(window.window_minutes).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let monthly = snapshot
        .monthly
        .as_ref()
        .map(|window| window.rate_window(Some(MONTHLY_MINUTES)))
        .transpose()?
        .flatten();
    let rolling = snapshot
        .rolling
        .as_ref()
        .map(|window| window.rate_window(Some(ROLLING_MINUTES)))
        .transpose()?
        .flatten();
    let primary = rolling.clone().or_else(|| {
        if monthly.is_none() {
            fallback.first().cloned()
        } else {
            None
        }
    });
    let secondary = if let Some(monthly) = monthly.clone() {
        Some(monthly)
    } else if rolling.is_some() {
        fallback.first().cloned()
    } else if primary.is_some() {
        fallback.get(1).cloned()
    } else {
        None
    };
    let has_windows = primary.is_some() || secondary.is_some();
    let login_method = snapshot
        .plan_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| match snapshot.subscription_state {
            SubscriptionState::Active => None,
            SubscriptionState::Inactive => Some("No active subscription".to_owned()),
            SubscriptionState::Unknown if has_windows => None,
            SubscriptionState::Unknown => Some("No usage data".to_owned()),
        });
    let renews_at = snapshot.subscription_renews_at.or_else(|| {
        snapshot
            .monthly
            .as_ref()
            .and_then(|window| window.resets_at)
    });
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(login_method)?
        .subscription_renews_at(renews_at);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("chutes", "api")?.build()
}

fn parse_snapshot(value: &Value) -> ChutesSnapshot {
    let owned_root;
    let root = match value {
        Value::Object(root) => root,
        Value::Array(items) => {
            owned_root = Map::from_iter([("quotas".to_owned(), Value::Array(items.clone()))]);
            &owned_root
        }
        _ => {
            owned_root = Map::new();
            &owned_root
        }
    };
    let data_root = first_value(root, &["data", "result"])
        .and_then(Value::as_object)
        .unwrap_or(root);
    let subscription = first_dictionary(
        root,
        data_root,
        &[
            "subscription",
            "subscription_usage",
            "subscriptionUsage",
            "current_subscription",
            "currentSubscription",
            "plan",
        ],
    );
    let explicit_rolling = first_dictionary(root, data_root, ROLLING_PAYLOAD_KEYS)
        .and_then(|payload| parse_quota(payload, Some("4-hour quota"), Some(ROLLING_MINUTES)));
    let explicit_monthly = first_dictionary(root, data_root, MONTHLY_PAYLOAD_KEYS)
        .and_then(|payload| parse_quota(payload, Some("Monthly quota"), Some(MONTHLY_MINUTES)));
    let quota_windows = fallback_quota_objects(root, data_root)
        .iter()
        .filter_map(|payload| parse_quota(payload, None, None))
        .collect::<Vec<_>>();
    let rolling = explicit_rolling.or_else(|| {
        quota_windows
            .iter()
            .find(|window| window_kind(window) == Some(WindowKind::Rolling))
            .cloned()
    });
    let monthly = explicit_monthly.or_else(|| {
        quota_windows
            .iter()
            .find(|window| window_kind(window) == Some(WindowKind::Monthly))
            .cloned()
    });
    let fallback = quota_windows
        .into_iter()
        .filter(|window| Some(window) != rolling.as_ref() && Some(window) != monthly.as_ref())
        .collect();
    ChutesSnapshot {
        rolling,
        monthly,
        fallback,
        subscription_state: subscription_state(root, data_root, subscription),
        plan_name: plan_name(root, data_root, subscription),
        subscription_renews_at: subscription_renews_at(root, data_root, subscription),
    }
}

fn parse_quota(
    payload: &Map<String, Value>,
    default_label: Option<&str>,
    default_minutes: Option<i64>,
) -> Option<QuotaWindow> {
    let label = first_string(payload, LABEL_KEYS).or_else(|| default_label.map(str::to_owned));
    let limit = first_double(payload, LIMIT_KEYS);
    let used = first_double(payload, USED_KEYS);
    let remaining = first_double(payload, REMAINING_KEYS);
    let mut used_percent = normalized_percent(first_double(payload, PERCENT_USED_KEYS));
    if used_percent.is_none()
        && let Some(remaining_percent) =
            normalized_percent(first_double(payload, PERCENT_REMAINING_KEYS))
    {
        used_percent = Some(100.0 - remaining_percent);
    }
    let window_minutes = window_minutes(payload).or(default_minutes);
    let resets_at = first_date(payload, RESET_KEYS);
    let unit = first_string(payload, UNIT_KEYS).or_else(|| Some("credits".to_owned()));
    let quota = QuotaWindow {
        label,
        used,
        limit,
        remaining,
        used_percent,
        window_minutes,
        resets_at,
        unit,
    };
    quota.usage_percent().map(|_| quota)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowKind {
    Rolling,
    Monthly,
}

fn window_kind(window: &QuotaWindow) -> Option<WindowKind> {
    let label = [window.label.as_deref(), window.unit.as_deref()]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    if label.contains("rolling")
        || label.contains("4h")
        || label.contains("4 h")
        || label.contains("4-hour")
        || label.contains("four hour")
        || label.contains("four-hour")
        || window.window_minutes == Some(ROLLING_MINUTES)
    {
        Some(WindowKind::Rolling)
    } else if label.contains("month")
        || label.contains("billing")
        || label.contains("subscription")
        || window
            .window_minutes
            .is_some_and(|minutes| minutes >= 28 * 24 * 60)
    {
        Some(WindowKind::Monthly)
    } else {
        None
    }
}

fn subscription_state(
    root: &Map<String, Value>,
    data_root: &Map<String, Value>,
    subscription: Option<&Map<String, Value>>,
) -> SubscriptionState {
    if let Some(active) = first_bool(root, ACTIVE_KEYS)
        .or_else(|| first_bool(data_root, ACTIVE_KEYS))
        .or_else(|| subscription.and_then(|value| first_bool(value, ACTIVE_KEYS)))
    {
        return if active {
            SubscriptionState::Active
        } else {
            SubscriptionState::Inactive
        };
    }
    let status = first_string(root, STATUS_KEYS)
        .or_else(|| first_string(data_root, STATUS_KEYS))
        .or_else(|| subscription.and_then(|value| first_string(value, STATUS_KEYS)))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if status.contains("active") && !status.contains("inactive") {
        SubscriptionState::Active
    } else if ["free", "inactive", "cancel", "none", "expired"]
        .iter()
        .any(|needle| status.contains(needle))
    {
        SubscriptionState::Inactive
    } else {
        SubscriptionState::Unknown
    }
}

fn plan_name(
    root: &Map<String, Value>,
    data_root: &Map<String, Value>,
    subscription: Option<&Map<String, Value>>,
) -> Option<String> {
    first_string(root, PLAN_KEYS)
        .or_else(|| first_string(data_root, PLAN_KEYS))
        .or_else(|| subscription.and_then(|value| first_string(value, PLAN_KEYS)))
}

fn subscription_renews_at(
    root: &Map<String, Value>,
    data_root: &Map<String, Value>,
    subscription: Option<&Map<String, Value>>,
) -> Option<Timestamp> {
    first_date(root, RESET_KEYS)
        .or_else(|| first_date(data_root, RESET_KEYS))
        .or_else(|| subscription.and_then(|value| first_date(value, RESET_KEYS)))
}

fn fallback_quota_objects(
    root: &Map<String, Value>,
    data_root: &Map<String, Value>,
) -> Vec<Map<String, Value>> {
    let mut results = Vec::new();
    for candidate in [
        first_value(root, QUOTA_CONTAINER_KEYS),
        first_value(data_root, QUOTA_CONTAINER_KEYS),
        Some(&Value::Object(data_root.clone())),
        Some(&Value::Object(root.clone())),
    ]
    .into_iter()
    .flatten()
    {
        extract_quota_objects(candidate, 0, &mut results);
    }
    let mut seen = BTreeSet::new();
    results.retain(|object| {
        serde_json::to_string(object)
            .ok()
            .is_none_or(|key| seen.insert(key))
    });
    results
}

fn extract_quota_objects(value: &Value, depth: usize, results: &mut Vec<Map<String, Value>>) {
    if depth >= MAX_NESTING_DEPTH {
        return;
    }
    match value {
        Value::Array(items) => {
            for item in items {
                extract_quota_objects(item, depth + 1, results);
            }
        }
        Value::Object(object) => {
            if is_quota_payload(object) {
                results.push(object.clone());
            }
            for item in object.values() {
                extract_quota_objects(item, depth + 1, results);
            }
        }
        _ => {}
    }
}

fn is_quota_payload(payload: &Map<String, Value>) -> bool {
    first_double(payload, LIMIT_KEYS).is_some()
        || first_double(payload, USED_KEYS).is_some()
        || first_double(payload, REMAINING_KEYS).is_some()
        || first_double(payload, PERCENT_USED_KEYS).is_some()
        || first_double(payload, PERCENT_REMAINING_KEYS).is_some()
}

fn quota_definitions(value: &Value) -> Vec<Map<String, Value>> {
    if let Value::Array(items) = value {
        return items.iter().filter_map(Value::as_object).cloned().collect();
    }
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    if let Some(items) = root.get("quotas").and_then(Value::as_array) {
        return items.iter().filter_map(Value::as_object).cloned().collect();
    }
    if let Some(items) = root.get("data").and_then(Value::as_array) {
        return items.iter().filter_map(Value::as_object).cloned().collect();
    }
    root.get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("quotas"))
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items.iter().filter_map(Value::as_object).cloned().collect()
        })
}

fn quota_identifier(definition: &Map<String, Value>) -> Option<String> {
    for key in ["chute_id", "chuteId", "id"] {
        let Some(value) = definition.get(key) else {
            continue;
        };
        let identifier = match value {
            Value::String(value) => value.trim().to_owned(),
            Value::Number(value) => value.to_string(),
            _ => continue,
        };
        if !identifier.is_empty()
            && identifier.len() <= MAX_QUOTA_IDENTIFIER_BYTES
            && !identifier.chars().any(char::is_control)
        {
            return Some(identifier);
        }
    }
    None
}

fn response_dictionary(value: &Value) -> Option<&Map<String, Value>> {
    let dictionary = value.as_object()?;
    dictionary
        .get("data")
        .and_then(Value::as_object)
        .or_else(|| dictionary.get("result").and_then(Value::as_object))
        .or(Some(dictionary))
}

fn first_dictionary<'a>(
    root: &'a Map<String, Value>,
    data_root: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    first_value(root, keys)
        .and_then(Value::as_object)
        .or_else(|| first_value(data_root, keys).and_then(Value::as_object))
}

fn first_value<'a>(dictionary: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        let normalized = normalized_key(key);
        if let Some((_, value)) = dictionary
            .iter()
            .find(|(candidate, _)| normalized_key(candidate) == normalized)
        {
            return Some(value);
        }
    }
    None
}

fn normalized_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn first_string(dictionary: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    match first_value(dictionary, keys)? {
        Value::String(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_owned())
        }
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn first_bool(dictionary: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    match first_value(dictionary, keys)? {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_f64().map(|value| value != 0.0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "active" => Some(true),
            "false" | "0" | "no" | "inactive" | "none" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn first_double(dictionary: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    double_value(first_value(dictionary, keys)?)
}

fn double_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(value) => value.as_f64().filter(|value| value.is_finite()),
        Value::String(value) => value
            .trim()
            .replace([',', '$', '%'], "")
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite()),
        _ => None,
    }
}

fn normalized_percent(value: Option<f64>) -> Option<f64> {
    let value = value?;
    if !value.is_finite() {
        return None;
    }
    Some(
        (if value.abs() < 1.0 {
            value * 100.0
        } else {
            value
        })
        .clamp(0.0, 100.0),
    )
}

fn first_date(dictionary: &Map<String, Value>, keys: &[&str]) -> Option<Timestamp> {
    timestamp_value(first_value(dictionary, keys)?)
}

fn timestamp_value(value: &Value) -> Option<Timestamp> {
    match value {
        Value::Number(value) => value
            .to_string()
            .parse::<Decimal>()
            .ok()
            .and_then(epoch_timestamp),
        Value::String(value) => {
            let value = value.trim();
            value
                .parse::<Decimal>()
                .ok()
                .and_then(epoch_timestamp)
                .or_else(|| Timestamp::parse(value).ok())
        }
        _ => None,
    }
}

fn epoch_timestamp(mut value: Decimal) -> Option<Timestamp> {
    if value <= Decimal::ZERO {
        return None;
    }
    if value > Decimal::from(10_000_000_000_u64) {
        value /= Decimal::from(1000_u16);
    }
    Timestamp::from_unix_timestamp(value.trunc().to_i64()?).ok()
}

fn window_minutes(payload: &Map<String, Value>) -> Option<i64> {
    if let Some(value) = first_double(payload, WINDOW_MINUTE_KEYS) {
        return rounded_i64(value);
    }
    if let Some(value) = first_double(payload, WINDOW_HOUR_KEYS) {
        return rounded_i64(value * 60.0);
    }
    if let Some(value) = first_double(payload, WINDOW_DAY_KEYS) {
        return rounded_i64(value * 24.0 * 60.0);
    }
    if let Some(value) = first_double(payload, WINDOW_SECOND_KEYS) {
        return rounded_i64(value / 60.0);
    }
    first_string(payload, WINDOW_STRING_KEYS).and_then(|value| window_minutes_text(&value))
}

fn window_minutes_text(raw: &str) -> Option<i64> {
    let compact = raw.trim().to_ascii_lowercase().replace(' ', "");
    let split = compact
        .find(|character: char| !(character.is_ascii_digit() || matches!(character, '.' | '-')))
        .unwrap_or(compact.len());
    let value = compact[..split].parse::<f64>().ok()?;
    if value <= 0.0 {
        return None;
    }
    let suffix = &compact[split..];
    let multiplier = if suffix.starts_with("min") || suffix == "m" {
        1.0
    } else if suffix.starts_with("hour") || suffix.starts_with("hr") || suffix == "h" {
        60.0
    } else if suffix.starts_with("day") || suffix == "d" {
        24.0 * 60.0
    } else if suffix.starts_with("month") || suffix == "mo" {
        30.0 * 24.0 * 60.0
    } else {
        return None;
    };
    rounded_i64(value * multiplier)
}

fn rounded_i64(value: f64) -> Option<i64> {
    Decimal::from_f64(value)?
        .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
        .to_i64()
}

fn format_amount(value: f64) -> String {
    let rounded = value.round();
    if (value - rounded).abs() < 0.0001
        && let Some(value) = rounded_i64(value)
    {
        return value.to_string();
    }
    let mut text = format!("{value:.2}");
    while text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    text
}

fn is_authentication_error(error: &ClassifiedError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::AuthenticationExpired | ErrorKind::PermissionDenied
    )
}

fn append_segments(base: &Url, segments: &[&str]) -> Result<Url, ClassifiedError> {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    let mut path = url
        .path_segments_mut()
        .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
    path.pop_if_empty();
    for segment in segments {
        path.push(segment);
    }
    drop(path);
    Ok(url)
}

fn normalize_https_endpoint(raw: &str) -> Result<Url, ClassifiedError> {
    let candidate = if has_explicit_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(url)
}

fn has_explicit_scheme(raw: &str) -> bool {
    raw.find(':').is_some_and(|colon| {
        let scheme = &raw[..colon];
        !scheme.is_empty()
            && scheme.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                }
            })
    })
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

const ROLLING_PAYLOAD_KEYS: &[&str] = &[
    "rolling",
    "rolling_window",
    "rollingWindow",
    "rolling_4h",
    "rolling4h",
    "four_hour",
    "fourHour",
    "four_hour_usage",
    "fourHourUsage",
    "window_4h",
    "window4h",
];
const MONTHLY_PAYLOAD_KEYS: &[&str] = &[
    "monthly",
    "monthly_usage",
    "monthlyUsage",
    "subscription",
    "subscription_usage",
    "subscriptionUsage",
    "billing_period",
    "billingPeriod",
];
const QUOTA_CONTAINER_KEYS: &[&str] = &[
    "quotas",
    "quota",
    "quota_usage",
    "quotaUsage",
    "limits",
    "usage",
    "entries",
    "subscription_usage",
    "subscriptionUsage",
];
const LABEL_KEYS: &[&str] = &[
    "label",
    "name",
    "title",
    "type",
    "quota_type",
    "quotaType",
    "period",
    "window",
    "window_name",
    "windowName",
    "chute_id",
    "chuteId",
];
const LIMIT_KEYS: &[&str] = &[
    "limit",
    "cap",
    "max",
    "maximum",
    "quota",
    "quota_limit",
    "quotaLimit",
    "monthly_cap",
    "monthlyCap",
    "monthly_limit",
    "monthlyLimit",
    "request_limit",
    "requestLimit",
    "token_limit",
    "tokenLimit",
    "hard_limit",
    "hardLimit",
    "total",
];
const USED_KEYS: &[&str] = &[
    "used",
    "usage",
    "used_amount",
    "usedAmount",
    "consumed",
    "consumed_amount",
    "consumedAmount",
    "current",
    "current_usage",
    "currentUsage",
    "requests",
    "request_count",
    "requestCount",
    "tokens",
    "token_usage",
    "tokenUsage",
    "monthly_usage",
    "monthlyUsage",
];
const REMAINING_KEYS: &[&str] = &[
    "remaining",
    "available",
    "balance",
    "left",
    "remaining_amount",
    "remainingAmount",
    "available_amount",
    "availableAmount",
];
const PERCENT_USED_KEYS: &[&str] = &[
    "percent_used",
    "percentUsed",
    "usage_percent",
    "usagePercent",
    "used_percent",
    "usedPercent",
    "utilization",
    "utilization_percent",
    "utilizationPercent",
];
const PERCENT_REMAINING_KEYS: &[&str] = &[
    "percent_remaining",
    "percentRemaining",
    "remaining_percent",
    "remainingPercent",
];
const RESET_KEYS: &[&str] = &[
    "reset_at",
    "resetAt",
    "resets_at",
    "resetsAt",
    "reset_time",
    "resetTime",
    "next_reset_at",
    "nextResetAt",
    "renews_at",
    "renewsAt",
    "renewal_at",
    "renewalAt",
    "period_end",
    "periodEnd",
    "current_period_end",
    "currentPeriodEnd",
    "expires_at",
    "expiresAt",
    "window_end",
    "windowEnd",
    "end_time",
    "endTime",
];
const UNIT_KEYS: &[&str] = &["unit", "units", "currency", "quota_unit", "quotaUnit"];
const ACTIVE_KEYS: &[&str] = &[
    "active",
    "is_active",
    "isActive",
    "subscription_active",
    "subscriptionActive",
    "has_subscription",
    "hasSubscription",
];
const STATUS_KEYS: &[&str] = &[
    "status",
    "state",
    "subscription_status",
    "subscriptionStatus",
];
const PLAN_KEYS: &[&str] = &[
    "plan_name",
    "planName",
    "plan",
    "tier",
    "subscription_plan",
    "subscriptionPlan",
    "subscription_tier",
    "subscriptionTier",
];
const WINDOW_MINUTE_KEYS: &[&str] = &[
    "window_minutes",
    "windowMinutes",
    "period_minutes",
    "periodMinutes",
    "duration_minutes",
    "durationMinutes",
];
const WINDOW_HOUR_KEYS: &[&str] = &[
    "window_hours",
    "windowHours",
    "period_hours",
    "periodHours",
    "duration_hours",
    "durationHours",
];
const WINDOW_DAY_KEYS: &[&str] = &[
    "window_days",
    "windowDays",
    "period_days",
    "periodDays",
    "duration_days",
    "durationDays",
];
const WINDOW_SECOND_KEYS: &[&str] = &[
    "window_seconds",
    "windowSeconds",
    "period_seconds",
    "periodSeconds",
    "duration_seconds",
    "durationSeconds",
];
const WINDOW_STRING_KEYS: &[&str] = &["window", "period", "interval", "duration"];
