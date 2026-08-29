//! `ElevenLabs` subscription-credit usage via its fixed API-key endpoint.

use std::time::Duration;

use oab_domain::{
    BoundedText, ClassifiedError, ErrorKind, NamedRateWindow, ProviderId, Timestamp, UsageSample,
};
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{
    UsageSampleBuilder, count_window, format_integer, system_timestamp, timestamp_from_unix,
};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.elevenlabs.io";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Native `ElevenLabs` provider adapter.
pub struct ElevenLabsProvider {
    client: FixedApiClient,
}

impl ElevenLabsProvider {
    /// Creates the production fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API-configuration error.
    pub fn new(
        scope: oab_domain::AccountScope,
        credential: ApiKeyCredential,
    ) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            "xi-api-key",
            credential,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// This seam supports deterministic loopback fixtures without weakening
    /// the production constructor's fixed HTTPS origin.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::ElevenLabs {
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
        let url = subscription_url(self.client.base_url());
        let response = self.client.get(context, url).await?;
        parse_usage(response.body(), context.scope().clone(), fetched_at)
    }
}

impl ProviderAdapter for ElevenLabsProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::ElevenLabs)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct SubscriptionResponse {
    tier: Option<String>,
    character_count: i64,
    character_limit: i64,
    voice_slots_used: Option<i64>,
    professional_voice_slots_used: Option<i64>,
    voice_limit: Option<i64>,
    professional_voice_limit: Option<i64>,
    #[serde(rename = "current_overage")]
    _current_overage: Option<Overage>,
    status: Option<String>,
    next_character_count_reset_unix: Option<i64>,
}

#[derive(Deserialize)]
struct Overage {
    #[serde(rename = "amount")]
    _amount: Option<String>,
    #[serde(rename = "currency")]
    _currency: Option<String>,
}

fn parse_usage(
    bytes: &[u8],
    scope: oab_domain::AccountScope,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let response: SubscriptionResponse =
        serde_json::from_slice(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let resets_at = response
        .next_character_count_reset_unix
        .map(timestamp_from_unix)
        .transpose()?;
    let summary = format!(
        "{} / {} credits",
        format_integer(response.character_count),
        format_integer(response.character_limit)
    );
    let primary = count_window(
        response.character_count,
        response.character_limit,
        resets_at,
        Some(summary),
    )?;
    let mut extra_windows = Vec::new();
    push_voice_window(
        &mut extra_windows,
        "voice-slots",
        "Voice slots",
        response.voice_slots_used,
        response.voice_limit,
    )?;
    push_voice_window(
        &mut extra_windows,
        "professional-voices",
        "Professional voices",
        response.professional_voice_slots_used,
        response.professional_voice_limit,
    )?;

    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .extra_windows(extra_windows)
        .login_method(display_tier(
            response.tier.as_deref(),
            response.status.as_deref(),
        ))?
        .provenance("elevenlabs", "api")?
        .build()
}

fn push_voice_window(
    windows: &mut Vec<NamedRateWindow>,
    id: &'static str,
    title: &'static str,
    used: Option<i64>,
    limit: Option<i64>,
) -> Result<(), ClassifiedError> {
    let (Some(used), Some(limit)) = (used, limit) else {
        return Ok(());
    };
    if limit <= 0 {
        return Ok(());
    }
    let window = count_window(used, limit, None, Some(format!("{used} / {limit}")))?;
    let id = BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let title = BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    windows.push(NamedRateWindow::new(id, title, window));
    Ok(())
}

fn display_tier(tier: Option<&str>, status: Option<&str>) -> Option<String> {
    let tier = tier.map(str::trim).filter(|value| !value.is_empty());
    let status = status.map(str::trim).filter(|value| !value.is_empty());
    let Some(tier) = tier else {
        return status.map(str::to_owned);
    };
    let mut display = title_case(&tier.replace('_', " "));
    if let Some(status) = status.filter(|status| !status.eq_ignore_ascii_case("active")) {
        display.push_str(" · ");
        display.push_str(status);
    }
    Some(display)
}

fn title_case(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            let mut characters = word.chars();
            let Some(first) = characters.next() else {
                return String::new();
            };
            first
                .to_uppercase()
                .chain(characters.flat_map(char::to_lowercase))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn subscription_url(base_url: &Url) -> Url {
    let mut url = base_url.clone();
    let base_path = url.path().trim_end_matches('/');
    let suffix = if base_path
        .rsplit_once('/')
        .map_or(base_path, |(_, tail)| tail)
        .eq_ignore_ascii_case("v1")
    {
        "user/subscription"
    } else {
        "v1/user/subscription"
    };
    let path = if base_path.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    url
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
