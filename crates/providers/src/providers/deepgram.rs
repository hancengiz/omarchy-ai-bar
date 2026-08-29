//! Deepgram Management API project discovery and usage aggregation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, DetailRow, DetailSection, DetailSensitivity, ErrorKind,
    ProviderId, Timestamp, UsageSample,
};
use rust_decimal::{Decimal, RoundingStrategy};
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, format_integer, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "DEEPGRAM_API_KEY";
const PROJECT_ID: &str = "DEEPGRAM_PROJECT_ID";
const API_URL: &str = "DEEPGRAM_API_URL";
const DEFAULT_API_URL: &str = "https://api.deepgram.com/v1";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROJECTS: usize = 100;
const MAX_PROJECT_TEXT_BYTES: usize = 200;

/// Validated Deepgram endpoint, optional project selection, and secret.
pub struct DeepgramSettings {
    credential: ApiKeyCredential,
    endpoint: Url,
    endpoint_class: EndpointClass,
    project_id: Option<String>,
}

impl DeepgramSettings {
    /// Resolves the pinned baseline's environment settings.
    ///
    /// Bare endpoint hosts are normalized to HTTPS. Explicit HTTP, URL user
    /// information, queries, and fragments fail closed.
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
        let project_id = environment
            .get(PROJECT_ID)
            .and_then(|value| clean_setting(value))
            .map(validate_project_text)
            .transpose()?;
        Ok(Self {
            credential,
            endpoint,
            endpoint_class,
            project_id,
        })
    }
}

impl Debug for DeepgramSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeepgramSettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .field("endpoint_class", &self.endpoint_class)
            .field(
                "project_id",
                &self.project_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Native Deepgram provider adapter.
pub struct DeepgramProvider {
    client: FixedApiClient,
    project_id: Option<String>,
}

impl DeepgramProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: DeepgramSettings) -> Result<Self, ClassifiedError> {
        let DeepgramSettings {
            credential,
            endpoint,
            endpoint_class,
            project_id,
        } = settings;
        let client = FixedApiClient::new_authorization_scheme(
            scope,
            endpoint,
            endpoint_class,
            "Token",
            credential,
            transport_config()?,
        )?;
        Self::from_client(client, project_id.as_deref())
    }

    /// Wraps an already validated account-scoped client and project selector.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider or invalid project text.
    pub fn from_client(
        client: FixedApiClient,
        project_id: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Deepgram {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let project_id = project_id
            .map(validate_project_text)
            .transpose()?
            .filter(|value| !value.is_empty());
        Ok(Self { client, project_id })
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
        let projects = self.projects(context).await?;
        let mut totals = UsageTotals::default();
        let mut start: Option<String> = None;
        let mut end: Option<String> = None;
        for project in &projects {
            let url = project_url(self.client.base_url(), &project.id, &["usage", "breakdown"])?;
            let payload: UsagePayload = self.client.get_json(context, url).await?.json()?;
            let parsed = parse_usage(payload)?;
            totals.add(&parsed)?;
            if let Some(candidate) = parsed.start
                && start.as_ref().is_none_or(|value| candidate < *value)
            {
                start = Some(candidate);
            }
            if let Some(candidate) = parsed.end
                && end.as_ref().is_none_or(|value| candidate > *value)
            {
                end = Some(candidate);
            }
        }
        normalize(
            context.scope().clone(),
            fetched_at,
            &projects,
            &totals,
            start.as_deref(),
            end.as_deref(),
        )
    }

    async fn projects(&self, context: &ProviderContext) -> Result<Vec<Project>, ClassifiedError> {
        if let Some(project_id) = &self.project_id {
            return Ok(vec![Project {
                id: project_id.clone(),
                name: None,
            }]);
        }
        let url = append_segments(self.client.base_url(), &["projects"])?;
        let payload: ProjectsPayload = self.client.get_json(context, url).await?.json()?;
        if payload.projects.is_empty() || payload.projects.len() > MAX_PROJECTS {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let mut seen = BTreeSet::new();
        let mut projects = Vec::with_capacity(payload.projects.len());
        for project in payload.projects {
            let id = validate_project_text(&project.project_id)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            if id.is_empty() || !seen.insert(id.clone()) {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            let name = project
                .name
                .map(|name| validate_project_name(&name))
                .transpose()?;
            projects.push(Project { id, name });
        }
        Ok(projects)
    }
}

impl ProviderAdapter for DeepgramProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Deepgram)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct ProjectsPayload {
    projects: Vec<ProjectPayload>,
}

#[derive(Deserialize)]
struct ProjectPayload {
    project_id: String,
    name: Option<String>,
}

struct Project {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct UsagePayload {
    start: Option<String>,
    end: Option<String>,
    resolution: Option<ResolutionPayload>,
    results: Vec<UsageRow>,
}

#[derive(Deserialize)]
struct ResolutionPayload {
    #[serde(rename = "units")]
    _units: Option<String>,
    amount: Option<JsonNumber>,
}

#[derive(Deserialize)]
struct UsageRow {
    hours: Option<JsonNumber>,
    total_hours: Option<JsonNumber>,
    agent_hours: Option<JsonNumber>,
    tokens_in: Option<JsonNumber>,
    tokens_out: Option<JsonNumber>,
    tts_characters: Option<JsonNumber>,
    requests: Option<JsonNumber>,
}

#[derive(Clone, Copy)]
struct JsonNumber(Decimal);

impl<'de> Deserialize<'de> for JsonNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        number
            .to_string()
            .parse::<Decimal>()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

#[derive(Default)]
struct UsageTotals {
    start: Option<String>,
    end: Option<String>,
    hours: Decimal,
    total_hours: Decimal,
    agent_hours: Decimal,
    tokens_in: i64,
    tokens_out: i64,
    tts_characters: i64,
    requests: i64,
}

impl UsageTotals {
    fn add(&mut self, other: &Self) -> Result<(), ClassifiedError> {
        self.hours = self
            .hours
            .checked_add(other.hours)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        self.total_hours = self
            .total_hours
            .checked_add(other.total_hours)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        self.agent_hours = self
            .agent_hours
            .checked_add(other.agent_hours)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        self.tokens_in = checked_add(self.tokens_in, other.tokens_in)?;
        self.tokens_out = checked_add(self.tokens_out, other.tokens_out)?;
        self.tts_characters = checked_add(self.tts_characters, other.tts_characters)?;
        self.requests = checked_add(self.requests, other.requests)?;
        Ok(())
    }
}

fn parse_usage(payload: UsagePayload) -> Result<UsageTotals, ClassifiedError> {
    if let Some(resolution) = payload.resolution
        && let Some(amount) = resolution.amount
    {
        integer(amount)?;
    }
    let mut totals = UsageTotals {
        start: payload.start,
        end: payload.end,
        ..UsageTotals::default()
    };
    for row in payload.results {
        totals.hours = add_decimal(totals.hours, decimal(row.hours))?;
        totals.total_hours = add_decimal(totals.total_hours, decimal(row.total_hours))?;
        totals.agent_hours = add_decimal(totals.agent_hours, decimal(row.agent_hours))?;
        totals.tokens_in = checked_add(totals.tokens_in, optional_integer(row.tokens_in)?)?;
        totals.tokens_out = checked_add(totals.tokens_out, optional_integer(row.tokens_out)?)?;
        totals.tts_characters =
            checked_add(totals.tts_characters, optional_integer(row.tts_characters)?)?;
        totals.requests = checked_add(totals.requests, optional_integer(row.requests)?)?;
    }
    Ok(totals)
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    projects: &[Project],
    totals: &UsageTotals,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<UsageSample, ClassifiedError> {
    let mut rows = vec![detail_row(
        "Requests",
        format_integer(totals.requests),
        None,
    )?];
    if !totals.hours.is_zero() || !totals.total_hours.is_zero() {
        rows.push(detail_row(
            "Audio",
            format!("{} hours", format_decimal(totals.hours)),
            Some(format!(
                "{} billable hours",
                format_decimal(totals.total_hours)
            )),
        )?);
    }
    if !totals.agent_hours.is_zero() {
        rows.push(detail_row(
            "Agent hours",
            format_decimal(totals.agent_hours),
            None,
        )?);
    }
    if totals.tokens_in != 0 || totals.tokens_out != 0 {
        rows.push(detail_row(
            "Tokens",
            format_integer(checked_add(totals.tokens_in, totals.tokens_out)?),
            None,
        )?);
    }
    if totals.tts_characters != 0 {
        rows.push(detail_row(
            "TTS characters",
            format_integer(totals.tts_characters),
            None,
        )?);
    }
    if let (Some(start), Some(end)) = (start, end) {
        rows.push(detail_row("Period", format!("{start} to {end}"), None)?);
    }
    let section = DetailSection::new(Some("Usage summary".to_owned()), rows, None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let login_method = if projects.len() > 1 {
        format!("{} projects", projects.len())
    } else {
        let project = projects
            .first()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        format!(
            "Project: {}",
            project
                .name
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or(&project.id)
        )
    };
    UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some(login_method))?
        .detail_sections(vec![section])
        .provenance("deepgram", "api")?
        .build()
}

fn detail_row(
    label: &'static str,
    value: String,
    secondary: Option<String>,
) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, secondary, DetailSensitivity::Public)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn decimal(value: Option<JsonNumber>) -> Decimal {
    value.map_or(Decimal::ZERO, |value| value.0)
}

fn optional_integer(value: Option<JsonNumber>) -> Result<i64, ClassifiedError> {
    value.map_or(Ok(0), integer)
}

fn integer(value: JsonNumber) -> Result<i64, ClassifiedError> {
    if !value.0.fract().is_zero() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    value
        .0
        .try_into()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn checked_add(left: i64, right: i64) -> Result<i64, ClassifiedError> {
    left.checked_add(right)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn add_decimal(left: Decimal, right: Decimal) -> Result<Decimal, ClassifiedError> {
    left.checked_add(right)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn format_decimal(value: Decimal) -> String {
    let show_fraction = !value.fract().is_zero();
    let rounded = value.round_dp_with_strategy(1, RoundingStrategy::MidpointAwayFromZero);
    let raw = if show_fraction {
        format!("{rounded:.1}")
    } else {
        rounded.trunc().to_string()
    };
    let (integer, fraction) = raw
        .split_once('.')
        .map_or((raw.as_str(), None), |parts| (parts.0, Some(parts.1)));
    let integer = integer
        .parse::<i64>()
        .map_or_else(|_| integer.to_owned(), format_integer);
    fraction.map_or(integer.clone(), |fraction| format!("{integer}.{fraction}"))
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

fn validate_project_text(value: &str) -> Result<String, ClassifiedError> {
    if value.is_empty()
        || value.len() > MAX_PROJECT_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(value.to_owned())
}

fn validate_project_name(value: &str) -> Result<String, ClassifiedError> {
    if value.len() > MAX_PROJECT_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(value.to_owned())
}

fn project_url(base: &Url, project_id: &str, tail: &[&str]) -> Result<Url, ClassifiedError> {
    let mut segments = vec!["projects", project_id];
    segments.extend_from_slice(tail);
    append_segments(base, &segments)
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
