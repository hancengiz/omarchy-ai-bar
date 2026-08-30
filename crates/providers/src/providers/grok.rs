//! Grok Build billing adapter over the CLI's bounded JSON-RPC stdio surface.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsageSample,
    WindowDuration, WindowUsage,
};
use serde::Deserialize;
use serde_json::json;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::executable::ExecutablePath;
use crate::json_rpc_child::{JsonRpcChildError, JsonRpcChildRequest, JsonRpcVersion};
use crate::normalize::{UsageSampleBuilder, count_percent, system_timestamp};
use crate::registry::descriptor_for;

const MAX_RPC_FRAME_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const CHILD_ENVIRONMENT_ALLOWLIST: [&str; 13] = [
    "HOME",
    "PATH",
    "GROK_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
];

/// Already-resolved Grok executable and bounded child environment.
pub struct GrokSettings {
    executable: Option<ExecutablePath>,
    environment: BTreeMap<String, String>,
}

impl GrokSettings {
    #[must_use]
    pub fn new(executable: Option<ExecutablePath>, environment: BTreeMap<String, String>) -> Self {
        Self {
            executable,
            environment,
        }
    }
}

impl std::fmt::Debug for GrokSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrokSettings")
            .field("has_executable", &self.executable.is_some())
            .field("environment", &"<redacted>")
            .finish()
    }
}

/// One exact Grok Build account discovered and queried through its CLI.
pub struct GrokProvider {
    scope: AccountScope,
    settings: GrokSettings,
}

impl GrokProvider {
    /// Binds the Grok CLI to one exact account scope.
    ///
    /// # Errors
    ///
    /// Returns an API classification when the scope is not Grok.
    pub fn new(scope: AccountScope, settings: GrokSettings) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Grok {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { scope, settings })
    }

    async fn fetch_billing(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        let executable = self
            .settings
            .executable
            .as_ref()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let mut request = JsonRpcChildRequest::new(
            executable.clone(),
            ["agent", "stdio"],
            JsonRpcVersion::V2,
            MAX_RPC_FRAME_BYTES,
            MAX_STDERR_BYTES,
        )
        .map_err(|error| classify_rpc(&error))?
        .with_cleared_environment();
        for name in CHILD_ENVIRONMENT_ALLOWLIST {
            if let Some(value) = self.settings.environment.get(name) {
                request = request
                    .with_environment(name, value)
                    .map_err(|error| classify_rpc(&error))?;
            }
        }
        let mut child = request
            .spawn(context.cancellation())
            .await
            .map_err(|error| classify_rpc(&error))?;
        let initialized = child
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": "1",
                    "clientCapabilities": {
                        "fs": {"readTextFile": false, "writeTextFile": false},
                        "terminal": false
                    }
                })),
                Duration::from_secs(4),
                context.cancellation(),
            )
            .await;
        if let Err(error) = initialized {
            child.shutdown().await;
            return Err(classify_rpc(&error));
        }
        let result = child
            .request(
                "x.ai/billing",
                Some(json!({})),
                Duration::from_secs(3),
                context.cancellation(),
            )
            .await;
        child.shutdown().await;
        let billing = serde_json::from_value(result.map_err(|error| classify_rpc(&error))?)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        normalize_billing(self.scope.clone(), system_timestamp()?, billing)
    }
}

impl ProviderAdapter for GrokProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Grok)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move { self.fetch_billing(context).await })
    }
}

fn classify_rpc(error: &JsonRpcChildError) -> ClassifiedError {
    let kind = match error {
        JsonRpcChildError::Spawn => ErrorKind::MissingCredential,
        JsonRpcChildError::Cancelled
        | JsonRpcChildError::Timeout
        | JsonRpcChildError::StdinClosed
        | JsonRpcChildError::StdoutRead
        | JsonRpcChildError::StderrRead
        | JsonRpcChildError::Closed => ErrorKind::Network,
        JsonRpcChildError::StdoutTooLarge
        | JsonRpcChildError::StderrTooLarge
        | JsonRpcChildError::Protocol => ErrorKind::Parse,
        JsonRpcChildError::Remote(_) => ErrorKind::AuthenticationExpired,
        JsonRpcChildError::InvalidConfiguration => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrokBilling {
    billing_cycle: Option<GrokBillingCycle>,
    monthly_limit: Option<GrokCent>,
    usage: Option<GrokUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrokBillingCycle {
    billing_period_start: Option<String>,
    billing_period_end: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrokUsage {
    total_used: Option<GrokCent>,
}

#[derive(Debug, Deserialize)]
struct GrokCent {
    val: Option<i64>,
}

fn normalize_billing(
    scope: AccountScope,
    fetched_at: Timestamp,
    billing: GrokBilling,
) -> Result<UsageSample, ClassifiedError> {
    let limit = billing
        .monthly_limit
        .and_then(|value| value.val)
        .filter(|value| *value > 0)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let used = billing
        .usage
        .and_then(|usage| usage.total_used)
        .and_then(|value| value.val)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let (duration, reset) = billing.billing_cycle.map_or(Ok((None, None)), |cycle| {
        let start = cycle
            .billing_period_start
            .as_deref()
            .map(Timestamp::parse)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let end = cycle
            .billing_period_end
            .as_deref()
            .map(Timestamp::parse)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let duration = match (start, end) {
            (Some(start), Some(end)) if end > start => {
                let seconds = end.unix_timestamp() - start.unix_timestamp();
                Some(
                    WindowDuration::from_seconds(
                        u64::try_from(seconds)
                            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                    )
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                )
            }
            _ => None,
        };
        Ok((duration, end))
    })?;
    let primary = RateWindow::new(
        WindowUsage::known(count_percent(used, limit)?),
        duration,
        reset,
        None,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .login_method(Some("Grok Build".to_owned()))?
        .provenance("grok", "cli")?
        .build()
}

#[cfg(test)]
mod tests {
    use oab_domain::{AccountKey, ProviderInstanceId};

    use super::*;

    #[test]
    fn normalizes_grok_billing() {
        let billing: GrokBilling = serde_json::from_value(json!({
            "billingCycle": {
                "billingPeriodStart": "2026-08-01T00:00:00Z",
                "billingPeriodEnd": "2026-09-01T00:00:00Z"
            },
            "monthlyLimit": {"val": 10000},
            "usage": {"totalUsed": {"val": 2500}}
        }))
        .unwrap();
        let scope = AccountScope::new(
            ProviderId::Grok,
            ProviderInstanceId::new("default").unwrap(),
            AccountKey::new("ambient").unwrap(),
        );
        let sample = normalize_billing(
            scope,
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            billing,
        )
        .unwrap();
        let percent = sample.primary().unwrap().used_percent().unwrap().get();
        assert!((percent - 25.0).abs() < f64::EPSILON);
    }
}
