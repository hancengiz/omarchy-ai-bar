//! Wayfinder local-gateway health, routing, savings, and latency adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, DetailRow, DetailSection, DetailSensitivity, ErrorKind,
    ProviderId, Timestamp, UsageSample,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer};

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::EndpointPolicy;
use crate::normalize::{UsageSampleBuilder, format_integer, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportConfig};

const BASE_URL: &str = "WAYFINDER_GATEWAY_URL";
const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8088";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MODELS: usize = 512;
const MAX_MISSING_KEYS: usize = 512;
const MAX_ROUTES: usize = 512;
const DECISION_LATENCY_METRIC: &str = "wayfinder_router_decision_latency_seconds";

/// Validated Wayfinder gateway endpoint.
pub struct WayfinderSettings {
    endpoint: ConfiguredEndpoint,
}

impl WayfinderSettings {
    /// Resolves the optional override or the pinned loopback default.
    ///
    /// # Errors
    ///
    /// Returns a stable API error when an explicit override is unsafe.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let raw = environment
            .get(BASE_URL)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_BASE_URL);
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::LoopbackHttp)?;
        Ok(Self { endpoint })
    }
}

impl Debug for WayfinderSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WayfinderSettings")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Credentialless native Wayfinder gateway adapter.
pub struct WayfinderProvider {
    scope: AccountScope,
    endpoint: ConfiguredEndpoint,
    transport: HttpTransport,
}

impl WayfinderProvider {
    /// Creates the production exact-origin gateway client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid transport configuration.
    pub fn new(scope: AccountScope, settings: WayfinderSettings) -> Result<Self, ClassifiedError> {
        Self::from_endpoint(scope, settings.endpoint, transport_config()?)
    }

    /// Creates an account-scoped client for an already validated endpoint.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider or invalid policy.
    pub fn from_endpoint(
        scope: AccountScope,
        endpoint: ConfiguredEndpoint,
        config: TransportConfig,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Wayfinder {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let origin = endpoint.url().origin().ascii_serialization();
        let policy = EndpointPolicy::new([(origin, endpoint.class())])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport = HttpTransport::new(policy, config).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            endpoint,
            transport,
        })
    }

    /// Fetches and normalizes one deterministic sample timestamp.
    ///
    /// `/metrics` is best-effort; the three JSON endpoints are required.
    ///
    /// # Errors
    ///
    /// Returns stable classified transport or parse errors without gateway
    /// response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let health: HealthResponse = self.get_json(context, &["healthz"], &[]).await?.json()?;
        let models: ModelsResponse = self
            .get_json(context, &["router", "models"], &[])
            .await?
            .json()?;
        let savings: SavingsResponse = self
            .get_json(context, &["v1", "savings"], &[("period", "30d")])
            .await?
            .json()?;
        let metrics = match self.get(context, &["metrics"], &[], false).await {
            Ok(response) => std::str::from_utf8(response.body())
                .ok()
                .and_then(average_decision_milliseconds),
            Err(error) if context.cancellation().is_cancelled() => return Err(error),
            Err(_) => None,
        };
        normalize(
            context.scope().clone(),
            fetched_at,
            health,
            &models,
            savings,
            metrics,
        )
    }

    async fn get_json(
        &self,
        context: &ProviderContext,
        path: &[&str],
        query: &[(&str, &str)],
    ) -> Result<HttpResponse, ClassifiedError> {
        self.get(context, path, query, true).await
    }

    async fn get(
        &self,
        context: &ProviderContext,
        path: &[&str],
        query: &[(&str, &str)],
        json: bool,
    ) -> Result<HttpResponse, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ApiKey {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let mut url = self.endpoint.path(None, path)?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let request = if json {
            HttpRequest::get_json(url)
        } else {
            HttpRequest::get(url)
        };
        self.transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())
    }
}

impl ProviderAdapter for WayfinderProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Wayfinder)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
    offline: bool,
    missing_keys: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ModelsResponse {
    models: Vec<Model>,
    dry_run: bool,
}

#[derive(Deserialize)]
struct Model {
    #[serde(rename = "name")]
    _name: String,
}

#[derive(Deserialize)]
struct SavingsResponse {
    priced: bool,
    requests: i64,
    #[serde(rename = "tokens")]
    _tokens: i64,
    #[serde(rename = "realized")]
    _realized: JsonDecimal,
    #[serde(rename = "baseline")]
    _baseline: JsonDecimal,
    saved: JsonDecimal,
    saved_pct: JsonDecimal,
    by_route: BTreeMap<String, RouteBucket>,
}

#[derive(Deserialize)]
struct RouteBucket {
    requests: i64,
    #[serde(rename = "saved")]
    _saved: JsonDecimal,
    #[serde(rename = "tokens")]
    _tokens: i64,
}

#[derive(Clone, Copy)]
struct JsonDecimal(Decimal);

impl<'de> Deserialize<'de> for JsonDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        let raw = number.to_string();
        Decimal::from_scientific(&raw)
            .or_else(|_| raw.parse())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

struct RouteSummary {
    name: String,
    requests: i64,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    health: HealthResponse,
    models: &ModelsResponse,
    savings: SavingsResponse,
    average_decision_ms: Option<f64>,
) -> Result<UsageSample, ClassifiedError> {
    let missing_keys = health.missing_keys.unwrap_or_default();
    if models.models.len() > MAX_MODELS
        || missing_keys.len() > MAX_MISSING_KEYS
        || savings.by_route.len() > MAX_ROUTES
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut routes = savings
        .by_route
        .into_iter()
        .map(|(name, bucket)| RouteSummary {
            name,
            requests: bucket.requests,
        })
        .collect::<Vec<_>>();
    routes.sort_by(|left, right| {
        right
            .requests
            .cmp(&left.requests)
            .then_with(|| left.name.cmp(&right.name))
    });
    let model_count = models.models.len();
    let gateway_summary =
        gateway_summary(&health.status, model_count, health.offline, models.dry_run);
    let status_label = status_label(
        &health.status,
        health.offline,
        models.dry_run,
        missing_keys.len(),
    );
    let mut rows = vec![detail_row("Gateway", gateway_summary)?];
    if let Some(routed) = routed_summary(savings.requests, &routes) {
        rows.push(detail_row("Routed", routed)?);
    }
    if let Some(saved) = saved_summary(
        savings.requests,
        savings.saved.0,
        savings.saved_pct.0,
        savings.priced,
    ) {
        rows.push(detail_row("Saved", saved)?);
    }
    if let Some(milliseconds) = average_decision_ms {
        rows.push(detail_row("Avg decision", format!("{milliseconds:.1} ms"))?);
    }
    let section = DetailSection::new(Some("Usage".to_owned()), rows, None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    UsageSampleBuilder::new(scope, fetched_at)
        .organization(Some(format!(
            "{} · local gateway",
            model_count_label(model_count)
        )))?
        .login_method(Some(status_label))?
        .detail_sections(vec![section])
        .provenance("wayfinder", "api")?
        .build()
}

fn status_label(status: &str, offline: bool, dry_run: bool, missing_count: usize) -> String {
    if offline {
        return "Offline mode".to_owned();
    }
    if dry_run {
        return "Dry run".to_owned();
    }
    if status == "degraded" {
        return match missing_count {
            0 => "Degraded".to_owned(),
            1 => "Degraded — 1 key missing".to_owned(),
            count => format!("Degraded — {count} keys missing"),
        };
    }
    "Local gateway".to_owned()
}

fn gateway_summary(status: &str, model_count: usize, offline: bool, dry_run: bool) -> String {
    let mut summary = format!("{status} · {}", model_count_label(model_count));
    if offline {
        summary.push_str(" · offline");
    }
    if dry_run {
        summary.push_str(" · dry run");
    }
    summary
}

fn model_count_label(model_count: usize) -> String {
    if model_count == 1 {
        "1 model".to_owned()
    } else {
        format!("{model_count} models")
    }
}

fn routed_summary(requests: i64, routes: &[RouteSummary]) -> Option<String> {
    (requests > 0)
        .then(|| {
            routes
                .iter()
                .take(5)
                .map(|route| format!("{}: {}", route.name, format_integer(route.requests)))
                .collect::<Vec<_>>()
                .join(" · ")
        })
        .filter(|summary| !summary.is_empty())
}

fn saved_summary(
    requests: i64,
    saved: Decimal,
    saved_percent: Decimal,
    priced: bool,
) -> Option<String> {
    if requests <= 0 || saved <= Decimal::ZERO {
        return None;
    }
    let percentage = if saved_percent.fract().is_zero() {
        format!("{saved_percent:.0}")
    } else {
        format!("{saved_percent:.1}")
    };
    let comparison = format!("{percentage}% vs highest-cost route");
    if !priced {
        return Some(comparison);
    }
    let amount = if saved < Decimal::new(1, 2) {
        "<$0.01".to_owned()
    } else {
        format_usd(saved)
    };
    Some(format!("{amount} · {comparison}"))
}

fn detail_row(label: &str, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Public)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn average_decision_milliseconds(text: &str) -> Option<f64> {
    let mut sum = None;
    let mut count = None;
    for line in text.lines() {
        if let Some(value) = metric_value(line, &format!("{DECISION_LATENCY_METRIC}_sum")) {
            sum = Some(value);
        } else if let Some(value) = metric_value(line, &format!("{DECISION_LATENCY_METRIC}_count"))
        {
            count = Some(value);
        }
    }
    let (Some(sum), Some(count)) = (sum, count) else {
        return None;
    };
    (count > 0.0).then_some(sum / count * 1000.0)
}

fn metric_value(line: &str, name: &str) -> Option<f64> {
    let rest = line.strip_prefix(name)?;
    if !matches!(rest.as_bytes().first(), Some(b' ' | b'{')) {
        return None;
    }
    rest.split_ascii_whitespace().next_back()?.parse().ok()
}

fn format_usd(value: Decimal) -> String {
    format!("${:.2}", value.round_dp(2))
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(3),
        Duration::from_secs(5),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(100), Duration::from_secs(5)),
    )
    .map_err(|error| error.classified())
}
