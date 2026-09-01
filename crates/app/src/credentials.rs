//! Secret Service integration for explicit manual-session provider credentials.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_auth::credential_slot::CredentialSlotId;
use oab_auth::secret_store::{SecretKey, SecretServiceStore};
use oab_domain::{AccountKey, AccountScope, ProviderId, ProviderInstanceId};
use tokio::runtime::Builder;
use tokio::time::timeout;

pub(crate) const MANUAL_SESSION_PURPOSE: &str = "manual-session";
const CREDENTIAL_HYDRATION_TIMEOUT: Duration = Duration::from_secs(4);
const COPILOT_TOKEN_ENVIRONMENT: &str = "COPILOT_API_TOKEN";
const COPILOT_BUDGET_COOKIE_ENVIRONMENT: &str = "OMARCHY_AI_BAR_COPILOT_BUDGET_COOKIE";
const GROK_WEB_COOKIE_ENVIRONMENT: &str = "OMARCHY_AI_BAR_GROK_COOKIE";
pub(crate) const COPILOT_CREDENTIAL_OWNER_ENVIRONMENT: &str =
    "OMARCHY_AI_BAR_COPILOT_CREDENTIAL_OWNER";
pub(crate) const COPILOT_CREDENTIAL_OWNER_APPLICATION: &str = "application";
pub(crate) const COPILOT_CREDENTIAL_OWNER_EXPLICIT_ENVIRONMENT: &str = "environment";
pub(crate) const COPILOT_OAUTH_PURPOSE: &str = "oauth-token";
pub(crate) const COPILOT_OAUTH_ACCOUNT: &str = "ambient";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManualCredential {
    pub(crate) provider: &'static str,
    pub(crate) environment: &'static str,
}

// Keep one exact application-owned secret per provider.  The environment name
// is the provider adapter's canonical first-party input; explicit process
// environment values always retain precedence over these managed values.
//
// The on-disk Secret Service purpose remains `manual-session` for backwards
// compatibility with credentials saved by 0.2.x, including z.ai keys.  The
// command and UI present the broader, accurate term "managed credential".
pub(crate) const MANUAL_CREDENTIALS: [ManualCredential; 54] = [
    manual("abacus", "OMARCHY_AI_BAR_ABACUS_COOKIE"),
    manual("aiand", "AIAND_API_KEY"),
    manual("alibaba", "OMARCHY_AI_BAR_ALIBABA_COOKIE"),
    manual("amp", "AMP_API_KEY"),
    manual("azureopenai", "AZURE_OPENAI_API_KEY"),
    manual("chutes", "CHUTES_API_KEY"),
    manual("clawrouter", "CLAWROUTER_API_KEY"),
    manual("clinepass", "CLINEPASS_API_KEY"),
    manual("codebuff", "CODEBUFF_API_KEY"),
    manual("commandcode", "OMARCHY_AI_BAR_COMMANDCODE_COOKIE"),
    manual("crof", "CROF_API_KEY"),
    manual("cursor", "OMARCHY_AI_BAR_CURSOR_COOKIE"),
    manual("deepgram", "DEEPGRAM_API_KEY"),
    manual("deepinfra", "DEEPINFRA_API_KEY"),
    manual("deepseek", "DEEPSEEK_API_KEY"),
    manual("devin", "OMARCHY_AI_BAR_DEVIN_TOKEN"),
    manual("doubao", "DOUBAO_API_KEY"),
    manual("elevenlabs", "ELEVENLABS_API_KEY"),
    manual("factory", "FACTORY_API_KEY"),
    manual("fireworks", "FIREWORKS_API_KEY"),
    manual("groq", "GROQ_API_KEY"),
    manual("ibmbob", "BOBSHELL_API_KEY"),
    manual("kimi", "KIMI_MANUAL_COOKIE"),
    manual("kilo", "KILO_API_KEY"),
    manual("litellm", "LITELLM_API_KEY"),
    manual("longcat", "OMARCHY_AI_BAR_LONGCAT_COOKIE"),
    manual("llmproxy", "LLM_PROXY_API_KEY"),
    manual("manus", "OMARCHY_AI_BAR_MANUS_COOKIE"),
    manual("mimo", "OMARCHY_AI_BAR_MIMO_COOKIE"),
    manual("minimax", "MINIMAX_COOKIE"),
    manual("mistral", "OMARCHY_AI_BAR_MISTRAL_COOKIE"),
    manual("moonshot", "MOONSHOT_API_KEY"),
    manual("neuralwatt", "NEURALWATT_API_KEY"),
    manual("notion", "OMARCHY_AI_BAR_NOTION_COOKIE"),
    manual("ollama", "OLLAMA_API_KEY"),
    manual("openai", "OPENAI_API_KEY"),
    manual("opencode", "OMARCHY_AI_BAR_OPENCODE_COOKIE"),
    manual("opencodego", "OPENCODE_API_KEY"),
    manual("openrouter", "OPENROUTER_API_KEY"),
    manual("perplexity", "OMARCHY_AI_BAR_PERPLEXITY_COOKIE"),
    manual("poe", "POE_API_KEY"),
    manual("qoder", "OMARCHY_AI_BAR_QODER_COOKIE"),
    manual("qwencloud", "OMARCHY_AI_BAR_QWENCLOUD_COOKIE"),
    manual("sakana", "OMARCHY_AI_BAR_SAKANA_COOKIE"),
    manual("stepfun", "OMARCHY_AI_BAR_STEPFUN_COOKIE"),
    manual("sub2api", "SUB2API_API_KEY"),
    manual("synthetic", "SYNTHETIC_API_KEY"),
    manual("t3chat", "OMARCHY_AI_BAR_T3CHAT_COOKIE"),
    manual("venice", "VENICE_API_KEY"),
    manual("warp", "WARP_API_KEY"),
    manual("xai", "XAI_MANAGEMENT_API_KEY"),
    manual("zoommate", "OMARCHY_AI_BAR_ZOOMMATE_COOKIE"),
    manual("zai", "Z_AI_API_KEY"),
    manual("zenmux", "ZENMUX_MANAGEMENT_API_KEY"),
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

pub(crate) fn copilot_oauth_key() -> Result<SecretKey, oab_auth::secret_store::SecretKeyError> {
    SecretKey::new("copilot", COPILOT_OAUTH_ACCOUNT, COPILOT_OAUTH_PURPOSE)
}

fn zai_api_key_slot() -> Option<SecretKey> {
    let scope = AccountScope::new(
        ProviderId::Zai,
        ProviderInstanceId::new("default").ok()?,
        AccountKey::new("ambient").ok()?,
    );
    CredentialSlotId::new(scope, "zai-api-key")
        .ok()
        .map(CredentialSlotId::into_secret_key)
}

fn copilot_budget_cookie_slot() -> Option<SecretKey> {
    let scope = AccountScope::new(
        ProviderId::Copilot,
        ProviderInstanceId::new("default").ok()?,
        AccountKey::new("ambient").ok()?,
    );
    CredentialSlotId::new(scope, "copilot-budget-cookie")
        .ok()
        .map(CredentialSlotId::into_secret_key)
}

fn grok_web_cookie_slot() -> Option<SecretKey> {
    let scope = AccountScope::new(
        ProviderId::Grok,
        ProviderInstanceId::new("default").ok()?,
        AccountKey::new("ambient").ok()?,
    );
    CredentialSlotId::new(scope, "grok-web-cookie")
        .ok()
        .map(CredentialSlotId::into_secret_key)
}

fn named_slot_when_environment_is_empty(
    environment: &BTreeMap<String, String>,
    environment_name: &str,
    slot: fn() -> Option<SecretKey>,
) -> Option<SecretKey> {
    environment
        .get(environment_name)
        .is_none_or(|value| value.trim().is_empty())
        .then(slot)
        .flatten()
}

/// Best-effort Secret Service hydration below explicit environment precedence.
pub(crate) fn hydrate_environment(environment: &mut BTreeMap<String, String>) {
    // This marker is application-owned metadata. Never trust or retain an
    // ambient value supplied under the internal name.
    environment.remove(COPILOT_CREDENTIAL_OWNER_ENVIRONMENT);
    let explicit_copilot_token = environment
        .get(COPILOT_TOKEN_ENVIRONMENT)
        .is_some_and(|value| !value.trim().is_empty());
    if explicit_copilot_token {
        environment.insert(
            COPILOT_CREDENTIAL_OWNER_ENVIRONMENT.to_owned(),
            COPILOT_CREDENTIAL_OWNER_EXPLICIT_ENVIRONMENT.to_owned(),
        );
    }
    if !environment.contains_key("DBUS_SESSION_BUS_ADDRESS") {
        return;
    }
    let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
        return;
    };
    let mut requested_keys = MANUAL_CREDENTIALS
        .iter()
        .filter(|entry| {
            environment
                .get(entry.environment)
                .is_none_or(String::is_empty)
        })
        .filter_map(|entry| SecretKey::new(entry.provider, "ambient", MANUAL_SESSION_PURPOSE).ok())
        .collect::<Vec<_>>();
    if !explicit_copilot_token && let Ok(key) = copilot_oauth_key() {
        requested_keys.push(key);
    }
    let named_zai_key =
        named_slot_when_environment_is_empty(environment, "Z_AI_API_KEY", zai_api_key_slot);
    if let Some(key) = named_zai_key.clone() {
        requested_keys.push(key);
    }
    let named_copilot_budget_key = named_slot_when_environment_is_empty(
        environment,
        COPILOT_BUDGET_COOKIE_ENVIRONMENT,
        copilot_budget_cookie_slot,
    );
    if let Some(key) = named_copilot_budget_key.clone() {
        requested_keys.push(key);
    }
    let named_grok_web_key = named_slot_when_environment_is_empty(
        environment,
        GROK_WEB_COOKIE_ENVIRONMENT,
        grok_web_cookie_slot,
    );
    if let Some(key) = named_grok_web_key.clone() {
        requested_keys.push(key);
    }
    let values = runtime.block_on(async move {
        timeout(CREDENTIAL_HYDRATION_TIMEOUT, async {
            let store = SecretServiceStore::connect().await.ok()?;
            let mut values = Vec::new();
            for (key, secret) in store.get_many(&requested_keys).await.ok()? {
                let Ok(value) = String::from_utf8(secret.expose_secret().to_vec()) else {
                    continue;
                };
                if key.provider() == "copilot"
                    && key.account() == COPILOT_OAUTH_ACCOUNT
                    && key.purpose() == COPILOT_OAUTH_PURPOSE
                {
                    if valid_copilot_token(&value) {
                        values.push((COPILOT_TOKEN_ENVIRONMENT.to_owned(), value));
                        values.push((
                            COPILOT_CREDENTIAL_OWNER_ENVIRONMENT.to_owned(),
                            COPILOT_CREDENTIAL_OWNER_APPLICATION.to_owned(),
                        ));
                    }
                    continue;
                }
                if named_zai_key.as_ref() == Some(&key) {
                    values.push(("Z_AI_API_KEY".to_owned(), value));
                    continue;
                }
                if named_copilot_budget_key.as_ref() == Some(&key) {
                    values.push((COPILOT_BUDGET_COOKIE_ENVIRONMENT.to_owned(), value));
                    continue;
                }
                if named_grok_web_key.as_ref() == Some(&key) {
                    values.push((GROK_WEB_COOKIE_ENVIRONMENT.to_owned(), value));
                    continue;
                }
                let Some(entry) = credential_for(key.provider()) else {
                    continue;
                };
                if key.account() == "ambient" && key.purpose() == MANUAL_SESSION_PURPOSE {
                    values.push((entry.environment.to_owned(), value));
                }
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

fn valid_copilot_token(value: &str) -> bool {
    let token = value.trim();
    !token.is_empty()
        && token.len() <= oab_auth::secret_store::MAX_SECRET_BYTES
        && !token.contains(['\r', '\n'])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn managed_credentials_have_unique_provider_and_environment_routes() {
        let providers = MANUAL_CREDENTIALS
            .iter()
            .map(|entry| entry.provider)
            .collect::<BTreeSet<_>>();
        let environments = MANUAL_CREDENTIALS
            .iter()
            .map(|entry| entry.environment)
            .collect::<BTreeSet<_>>();

        assert_eq!(providers.len(), MANUAL_CREDENTIALS.len());
        assert_eq!(environments.len(), MANUAL_CREDENTIALS.len());
        assert!(!providers.contains("copilot"));
        for entry in MANUAL_CREDENTIALS {
            assert_eq!(credential_for(entry.provider), Some(entry));
        }
    }

    #[test]
    fn copilot_uses_one_exact_app_owned_secret_key() {
        let key = copilot_oauth_key().expect("fixed Copilot OAuth key");
        assert_eq!(key.provider(), "copilot");
        assert_eq!(key.account(), "ambient");
        assert_eq!(key.purpose(), "oauth-token");
    }

    #[test]
    fn typed_zai_api_key_slot_is_disjoint_from_the_legacy_primary_key() {
        let named = zai_api_key_slot().expect("fixed z.ai API-key slot");
        let legacy = SecretKey::new("zai", "ambient", MANUAL_SESSION_PURPOSE)
            .expect("fixed legacy z.ai key");

        assert_eq!(named.provider(), "zai");
        assert_eq!(named.account(), "ambient");
        assert_eq!(named.purpose(), "credential-slot/v1/default/zai-api-key");
        assert_ne!(named, legacy);
    }

    #[test]
    fn copilot_budget_cookie_uses_a_separate_app_owned_slot() {
        let budget = copilot_budget_cookie_slot().expect("fixed Copilot budget slot");
        let oauth = copilot_oauth_key().expect("fixed Copilot OAuth key");

        assert_eq!(budget.provider(), "copilot");
        assert_eq!(budget.account(), "ambient");
        assert_eq!(
            budget.purpose(),
            "credential-slot/v1/default/copilot-budget-cookie"
        );
        assert_ne!(budget, oauth);
    }

    #[test]
    fn grok_web_cookie_uses_the_descriptor_named_slot() {
        let cookie = grok_web_cookie_slot().expect("fixed Grok web-cookie slot");

        assert_eq!(cookie.provider(), "grok");
        assert_eq!(cookie.account(), "ambient");
        assert_eq!(
            cookie.purpose(),
            "credential-slot/v1/default/grok-web-cookie"
        );
    }

    #[test]
    fn app_owned_tokens_are_bounded_without_assuming_github_prefixes() {
        assert!(valid_copilot_token("future-token-format"));
        assert!(!valid_copilot_token(""));
        assert!(!valid_copilot_token("token\nsecond-line"));
        assert!(!valid_copilot_token(
            &"x".repeat(oab_auth::secret_store::MAX_SECRET_BYTES + 1)
        ));
    }

    #[test]
    fn explicit_copilot_environment_ownership_is_derived_not_trusted() {
        let mut environment = BTreeMap::from([
            (
                COPILOT_TOKEN_ENVIRONMENT.to_owned(),
                "explicit-token".to_owned(),
            ),
            (
                COPILOT_CREDENTIAL_OWNER_ENVIRONMENT.to_owned(),
                COPILOT_CREDENTIAL_OWNER_APPLICATION.to_owned(),
            ),
        ]);
        hydrate_environment(&mut environment);
        assert_eq!(
            environment
                .get(COPILOT_CREDENTIAL_OWNER_ENVIRONMENT)
                .map(String::as_str),
            Some(COPILOT_CREDENTIAL_OWNER_EXPLICIT_ENVIRONMENT)
        );

        let mut without_token = BTreeMap::from([(
            COPILOT_CREDENTIAL_OWNER_ENVIRONMENT.to_owned(),
            COPILOT_CREDENTIAL_OWNER_APPLICATION.to_owned(),
        )]);
        hydrate_environment(&mut without_token);
        assert!(!without_token.contains_key(COPILOT_CREDENTIAL_OWNER_ENVIRONMENT));
    }
}
