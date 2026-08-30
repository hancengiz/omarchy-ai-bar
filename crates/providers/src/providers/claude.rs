//! Claude Code OAuth usage adapter for Linux.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, NamedRateWindow, ProviderId, RateWindow,
    Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::classify_https_endpoint;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const USAGE_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;

/// Credential discovery selected once while preserving file re-reads on each refresh.
pub enum ClaudeCredentialSource {
    Environment(Zeroizing<String>),
    File(PathBuf),
}

impl std::fmt::Debug for ClaudeCredentialSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Environment(_) => formatter.write_str("Environment(<redacted>)"),
            Self::File(_) => formatter.write_str("File(<redacted>)"),
        }
    }
}

/// Validated Claude Code host discovery inputs.
#[derive(Debug)]
pub struct ClaudeSettings {
    credentials: ClaudeCredentialSource,
}

impl ClaudeSettings {
    /// Resolves an explicit token or Claude Code's profile-owned credential file.
    /// Construction does not read the credential file.
    ///
    /// # Errors
    ///
    /// Returns a missing-credential classification when the trusted home is
    /// not absolute.
    pub fn resolve(
        environment: &BTreeMap<String, String>,
        home: &Path,
    ) -> Result<Self, ClassifiedError> {
        if let Some(token) = environment
            .get("CLAUDE_OAUTH_TOKEN")
            .or_else(|| environment.get("ANTHROPIC_OAUTH_TOKEN"))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            return Ok(Self {
                credentials: ClaudeCredentialSource::Environment(Zeroizing::new(token.to_owned())),
            });
        }
        if !home.is_absolute() {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let config_root = environment
            .get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
            .or_else(|| environment.get("CLAUDE_CONFIG_DIR"))
            .filter(|value| !value.is_empty())
            .map_or_else(|| home.join(".claude"), PathBuf::from);
        let config_root = if config_root.is_absolute() {
            config_root
        } else {
            home.join(config_root)
        };
        Ok(Self {
            credentials: ClaudeCredentialSource::File(config_root.join(".credentials.json")),
        })
    }
}

/// Claude OAuth usage fetched from the same endpoint as Claude Code.
pub struct ClaudeProvider {
    scope: AccountScope,
    settings: ClaudeSettings,
}

impl ClaudeProvider {
    /// Binds Claude usage to one exact account scope.
    ///
    /// # Errors
    ///
    /// Returns an API classification when the scope is not Claude.
    pub fn new(scope: AccountScope, settings: ClaudeSettings) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Claude {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { scope, settings })
    }

    async fn fetch_usage(&self, context: &ProviderContext) -> Result<UsageSample, ClassifiedError> {
        let credential = self.load_credential()?;
        let url = Url::parse(USAGE_ENDPOINT).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let class =
            classify_https_endpoint(&url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let config = TransportConfig::new(
            Duration::from_secs(5),
            Duration::from_secs(30),
            2 * 1024 * 1024,
            0,
            RetryPolicy::none(),
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client =
            FixedApiClient::new_bearer(self.scope.clone(), url.clone(), class, credential, config)?
                .with_source(ProviderSource::OAuth)?;
        let response = client
            .get_json_with_public_headers(
                context,
                url,
                &[
                    ("anthropic-beta", "oauth-2025-04-20"),
                    ("user-agent", "claude-code/2.1.0"),
                ],
            )
            .await?;
        let usage: ClaudeUsageResponse = response.json()?;
        normalize_usage(context.scope().clone(), system_timestamp()?, usage)
    }

    fn load_credential(&self) -> Result<ApiKeyCredential, ClassifiedError> {
        match &self.settings.credentials {
            ClaudeCredentialSource::Environment(token) => ApiKeyCredential::new(token.as_str()),
            ClaudeCredentialSource::File(path) => load_file_credential(path),
        }
    }
}

impl ProviderAdapter for ClaudeProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Claude)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move { self.fetch_usage(context).await })
    }
}

fn load_file_credential(path: &Path) -> Result<ApiKeyCredential, ClassifiedError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let bytes = fs::read(path).map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let root: CredentialRoot =
        serde_json::from_slice(&bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let token = root
        .claude_ai_oauth
        .and_then(|oauth| oauth.access_token)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    ApiKeyCredential::new(token)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialRoot {
    claude_ai_oauth: Option<CredentialOauth>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialOauth {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsageResponse {
    five_hour: Option<ClaudeUsageWindow>,
    seven_day: Option<ClaudeUsageWindow>,
    seven_day_opus: Option<ClaudeUsageWindow>,
    seven_day_sonnet: Option<ClaudeUsageWindow>,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsageWindow {
    utilization: Option<f64>,
    resets_at: Option<String>,
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: ClaudeUsageResponse,
) -> Result<UsageSample, ClassifiedError> {
    let primary = response
        .five_hour
        .map(|window| normalize_window(&window, 300))
        .transpose()?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .login_method(Some("Claude Code OAuth".to_owned()))?;
    if let Some(weekly) = response.seven_day {
        builder = builder.secondary(normalize_window(&weekly, 10_080)?);
    }
    let mut extra = Vec::new();
    for (id, title, window) in [
        ("opus", "Opus weekly", response.seven_day_opus),
        ("sonnet", "Sonnet weekly", response.seven_day_sonnet),
    ] {
        if let Some(window) = window {
            extra.push(NamedRateWindow::new(
                BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                normalize_window(&window, 10_080)?,
            ));
        }
    }
    builder
        .extra_windows(extra)
        .provenance("claude", "oauth")?
        .build()
}

fn normalize_window(
    window: &ClaudeUsageWindow,
    minutes: i64,
) -> Result<RateWindow, ClassifiedError> {
    let usage = match window.utilization {
        Some(value) if value.is_finite() => WindowUsage::known(
            UsagePercent::new(value.clamp(0.0, 100.0))
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        None => WindowUsage::unknown(),
    };
    let reset = window
        .resets_at
        .as_deref()
        .map(Timestamp::parse)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(usage, Some(duration), reset, None, None, false)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

#[cfg(test)]
mod tests {
    use oab_domain::{AccountKey, ProviderInstanceId};

    use super::*;

    #[test]
    fn normalizes_claude_oauth_windows() {
        let response: ClaudeUsageResponse = serde_json::from_str(
            r#"{
              "five_hour":{"utilization":42.5,"resets_at":"2026-08-30T12:00:00Z"},
              "seven_day":{"utilization":17.0,"resets_at":"2026-09-01T00:00:00Z"},
              "seven_day_opus":{"utilization":3.0,"resets_at":null}
            }"#,
        )
        .expect("Claude fixture");
        let scope = AccountScope::new(
            ProviderId::Claude,
            ProviderInstanceId::new("default").unwrap(),
            AccountKey::new("ambient").unwrap(),
        );
        let sample = normalize_usage(
            scope,
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            response,
        )
        .expect("normalized usage");
        let primary = sample.primary().unwrap().used_percent().unwrap().get();
        let secondary = sample.secondary().unwrap().used_percent().unwrap().get();
        assert!((primary - 42.5).abs() < f64::EPSILON);
        assert!((secondary - 17.0).abs() < f64::EPSILON);
        assert_eq!(sample.extra_windows().len(), 1);
    }
}
