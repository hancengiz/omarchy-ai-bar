//! Secret Service integration for explicit manual-session provider credentials.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_auth::secret_store::{SecretKey, SecretServiceStore, SecretStore};
use tokio::runtime::Builder;
use tokio::time::timeout;

pub(crate) const MANUAL_SESSION_PURPOSE: &str = "manual-session";
const SECRET_SERVICE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy)]
pub(crate) struct ManualCredential {
    pub(crate) provider: &'static str,
    pub(crate) environment: &'static str,
}

pub(crate) const MANUAL_CREDENTIALS: [ManualCredential; 20] = [
    manual("abacus", "OMARCHY_AI_BAR_ABACUS_COOKIE"),
    manual("alibaba", "OMARCHY_AI_BAR_ALIBABA_COOKIE"),
    manual("commandcode", "OMARCHY_AI_BAR_COMMANDCODE_COOKIE"),
    manual("cursor", "OMARCHY_AI_BAR_CURSOR_COOKIE"),
    manual("devin", "OMARCHY_AI_BAR_DEVIN_TOKEN"),
    manual("kimi", "KIMI_MANUAL_COOKIE"),
    manual("longcat", "OMARCHY_AI_BAR_LONGCAT_COOKIE"),
    manual("manus", "OMARCHY_AI_BAR_MANUS_COOKIE"),
    manual("mimo", "OMARCHY_AI_BAR_MIMO_COOKIE"),
    manual("minimax", "MINIMAX_COOKIE"),
    manual("mistral", "OMARCHY_AI_BAR_MISTRAL_COOKIE"),
    manual("notion", "OMARCHY_AI_BAR_NOTION_COOKIE"),
    manual("opencode", "OMARCHY_AI_BAR_OPENCODE_COOKIE"),
    manual("perplexity", "OMARCHY_AI_BAR_PERPLEXITY_COOKIE"),
    manual("qoder", "OMARCHY_AI_BAR_QODER_COOKIE"),
    manual("qwencloud", "OMARCHY_AI_BAR_QWENCLOUD_COOKIE"),
    manual("sakana", "OMARCHY_AI_BAR_SAKANA_COOKIE"),
    manual("stepfun", "OMARCHY_AI_BAR_STEPFUN_COOKIE"),
    manual("t3chat", "OMARCHY_AI_BAR_T3CHAT_COOKIE"),
    manual("zoommate", "OMARCHY_AI_BAR_ZOOMMATE_COOKIE"),
];

const fn manual(provider: &'static str, environment: &'static str) -> ManualCredential {
    ManualCredential {
        provider,
        environment,
    }
}

pub(crate) fn credential_for(provider: &str) -> Option<ManualCredential> {
    MANUAL_CREDENTIALS
        .iter()
        .copied()
        .find(|entry| entry.provider == provider)
}

/// Best-effort Secret Service hydration below explicit environment precedence.
pub(crate) fn hydrate_environment(environment: &mut BTreeMap<String, String>) {
    if !environment.contains_key("DBUS_SESSION_BUS_ADDRESS") {
        return;
    }
    let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
        return;
    };
    let values = runtime.block_on(async {
        timeout(SECRET_SERVICE_TIMEOUT, async {
            let store = SecretServiceStore::connect().await.ok()?;
            let mut values = Vec::new();
            for entry in MANUAL_CREDENTIALS {
                if environment
                    .get(entry.environment)
                    .is_some_and(|value| !value.is_empty())
                {
                    continue;
                }
                let key = SecretKey::new(entry.provider, "ambient", MANUAL_SESSION_PURPOSE).ok()?;
                let Some(secret) = store.get(&key).await.ok()? else {
                    continue;
                };
                let value = String::from_utf8(secret.expose_secret().to_vec()).ok()?;
                values.push((entry.environment.to_owned(), value));
            }
            Some(values)
        })
        .await
        .ok()
        .flatten()
    });
    if let Some(values) = values {
        environment.extend(values);
    }
}
