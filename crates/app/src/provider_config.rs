//! Non-secret provider-route settings projected into adapter configuration.

use std::collections::BTreeMap;

use oab_domain::ProviderId;
use oab_storage::config::{
    AppConfig, ProviderCookieSource, ProviderOptionValue, ProviderSourceMode,
};

/// Applies default-instance endpoint routes below explicit process-environment
/// precedence.
///
/// Provider adapters already validate their own endpoint and network policy.
/// This bridge only maps the ordinary configuration schema onto each
/// adapter's canonical endpoint setting; it never handles credentials.
pub(crate) fn apply_provider_route_environment(
    config: Option<&AppConfig>,
    environment: &mut BTreeMap<String, String>,
) {
    let Some(config) = config else {
        return;
    };

    for route in &config.providers {
        if route.instance_id.as_str() != "default" {
            continue;
        }
        if let (Some(environment_name), Some(endpoint)) = (
            endpoint_environment(route.id),
            route
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|endpoint| !endpoint.is_empty()),
        ) {
            insert_below_explicit_environment(environment, environment_name, endpoint);
        }

        match route.id {
            ProviderId::Grok => {
                if let Some(source) = route.options.source {
                    let source = match source {
                        ProviderSourceMode::Auto => "auto",
                        ProviderSourceMode::Cli => "cli",
                        ProviderSourceMode::Oauth => "oauth",
                        ProviderSourceMode::Web => "web",
                        _ => continue,
                    };
                    insert_below_explicit_environment(
                        environment,
                        "OMARCHY_AI_BAR_GROK_USAGE_SOURCE",
                        source,
                    );
                }
                if let Some(source) = route.options.cookie_source {
                    let source = match source {
                        ProviderCookieSource::Auto => "auto",
                        ProviderCookieSource::Manual => "manual",
                        ProviderCookieSource::Off => "off",
                    };
                    insert_below_explicit_environment(
                        environment,
                        "OMARCHY_AI_BAR_GROK_COOKIE_SOURCE",
                        source,
                    );
                }
            }
            ProviderId::Copilot => {
                if let Some(host) = route.options.enterprise_host.as_deref() {
                    insert_below_explicit_environment(
                        environment,
                        "OMARCHY_AI_BAR_COPILOT_ENTERPRISE_HOST",
                        host,
                    );
                }
                if let Some(enabled) = route.options.extras_enabled {
                    insert_below_explicit_environment(
                        environment,
                        "OMARCHY_AI_BAR_COPILOT_BUDGET_EXTRAS",
                        if enabled { "true" } else { "false" },
                    );
                }
                if let Some(source) = route.options.cookie_source {
                    let source = match source {
                        ProviderCookieSource::Auto => "auto",
                        ProviderCookieSource::Manual => "manual",
                        ProviderCookieSource::Off => "off",
                    };
                    insert_below_explicit_environment(
                        environment,
                        "OMARCHY_AI_BAR_COPILOT_BUDGET_COOKIE_SOURCE",
                        source,
                    );
                }
            }
            ProviderId::Zai => apply_zai_options(&route.options, environment),
            _ => {}
        }
    }
}

fn apply_zai_options(
    options: &oab_storage::config::ProviderOptions,
    environment: &mut BTreeMap<String, String>,
) {
    if let Some(region) = options.region.as_deref() {
        insert_below_explicit_environment(environment, "Z_AI_REGION", region);
    }
    if let Some(organization) = options.organization.as_deref() {
        insert_below_explicit_environment(environment, "Z_AI_ORGANIZATION", organization);
    }
    if let Some(project) = options.project.as_deref() {
        insert_below_explicit_environment(environment, "Z_AI_PROJECT", project);
    }
    if let Some(ProviderOptionValue::Text(scope)) = options.extensions.get("usage_scope") {
        insert_below_explicit_environment(environment, "Z_AI_USAGE_SCOPE", scope);
    } else if options.organization.is_some() && options.project.is_some() {
        insert_below_explicit_environment(environment, "Z_AI_USAGE_SCOPE", "team");
    }
}

fn insert_below_explicit_environment(
    environment: &mut BTreeMap<String, String>,
    name: &str,
    value: &str,
) {
    if environment
        .get(name)
        .is_none_or(|existing| existing.trim().is_empty())
    {
        environment.insert(name.to_owned(), value.to_owned());
    }
}

/// Returns the selected source for one default provider route.
#[must_use]
pub(crate) fn provider_source(
    config: Option<&AppConfig>,
    provider: ProviderId,
) -> Option<ProviderSourceMode> {
    default_route(config, provider).and_then(|route| route.options.source)
}

/// Returns one explicitly configured Boolean provider extension.
#[must_use]
pub(crate) fn provider_toggle(
    config: Option<&AppConfig>,
    provider: ProviderId,
    key: &str,
) -> Option<bool> {
    default_route(config, provider)
        .and_then(|route| route.options.extensions.get(key))
        .and_then(|value| match value {
            ProviderOptionValue::Boolean(value) => Some(*value),
            _ => None,
        })
}

fn default_route(
    config: Option<&AppConfig>,
    provider: ProviderId,
) -> Option<&oab_storage::config::ProviderConfig> {
    config.and_then(|config| {
        config
            .providers
            .iter()
            .find(|route| route.id == provider && route.instance_id.as_str() == "default")
    })
}

/// Whether the default provider route represents one unambiguous adapter
/// endpoint in this build.
#[must_use]
pub(crate) const fn supports_provider_endpoint(provider: ProviderId) -> bool {
    endpoint_environment(provider).is_some()
}

const fn endpoint_environment(provider: ProviderId) -> Option<&'static str> {
    match provider {
        ProviderId::AzureOpenAi => Some("AZURE_OPENAI_ENDPOINT"),
        ProviderId::Kimi => Some("KIMI_CODE_BASE_URL"),
        ProviderId::Ollama => Some("OLLAMA_API_URL"),
        ProviderId::Groq => Some("GROQ_API_URL"),
        ProviderId::ClawRouter => Some("CLAWROUTER_BASE_URL"),
        ProviderId::OpenRouter => Some("OPENROUTER_API_URL"),
        ProviderId::Wayfinder => Some("WAYFINDER_GATEWAY_URL"),
        ProviderId::Sub2Api => Some("SUB2API_BASE_URL"),
        ProviderId::LlmProxy => Some("LLM_PROXY_BASE_URL"),
        ProviderId::LiteLlm => Some("LITELLM_BASE_URL"),
        ProviderId::Neuralwatt => Some("NEURALWATT_API_URL"),
        ProviderId::Codebuff => Some("CODEBUFF_API_URL"),
        ProviderId::Chutes => Some("CHUTES_API_URL"),
        ProviderId::Deepgram => Some("DEEPGRAM_API_URL"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use oab_domain::{AccountKey, ProviderInstanceId};
    use oab_storage::config::{AccountConfig, CURRENT_SCHEMA_VERSION, ProviderConfig};

    use super::*;

    fn route(provider: ProviderId, instance: &str, endpoint: &str) -> ProviderConfig {
        ProviderConfig {
            id: provider,
            instance_id: ProviderInstanceId::new(instance).expect("canonical test instance"),
            enabled: true,
            endpoint: Some(endpoint.to_owned()),
            config_path: None,
            options: oab_storage::config::ProviderOptions::default(),
            accounts: vec![AccountConfig {
                id: AccountKey::new("ambient").expect("canonical test account"),
                enabled: true,
            }],
        }
    }

    fn config(routes: Vec<ProviderConfig>) -> AppConfig {
        let provider_order = routes.iter().map(|route| route.id).collect();
        AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            providers: routes,
            provider_order,
        }
    }

    #[test]
    fn projects_supported_default_route_endpoints() {
        let config = config(vec![
            route(ProviderId::AzureOpenAi, "default", "https://azure.example"),
            route(ProviderId::LiteLlm, "default", "http://127.0.0.1:4000"),
            route(
                ProviderId::OpenRouter,
                "default",
                "https://router.example/v1",
            ),
        ]);
        let mut environment = BTreeMap::new();

        apply_provider_route_environment(Some(&config), &mut environment);

        assert_eq!(
            environment.get("AZURE_OPENAI_ENDPOINT").map(String::as_str),
            Some("https://azure.example")
        );
        assert_eq!(
            environment.get("LITELLM_BASE_URL").map(String::as_str),
            Some("http://127.0.0.1:4000")
        );
        assert_eq!(
            environment.get("OPENROUTER_API_URL").map(String::as_str),
            Some("https://router.example/v1")
        );
    }

    #[test]
    fn explicit_environment_wins_and_nondefault_routes_are_ignored() {
        let config = config(vec![
            route(ProviderId::Groq, "default", "https://configured.example"),
            route(ProviderId::Ollama, "work", "https://ignored.example"),
        ]);
        let mut environment = BTreeMap::from([(
            "GROQ_API_URL".to_owned(),
            "https://explicit.example".to_owned(),
        )]);

        apply_provider_route_environment(Some(&config), &mut environment);

        assert_eq!(
            environment.get("GROQ_API_URL").map(String::as_str),
            Some("https://explicit.example")
        );
        assert!(!environment.contains_key("OLLAMA_API_URL"));
    }

    #[test]
    fn unsupported_provider_routes_are_not_projected() {
        let config = config(vec![route(
            ProviderId::Zai,
            "default",
            "https://not-a-single-zai-endpoint.example",
        )]);
        let mut environment = BTreeMap::new();

        apply_provider_route_environment(Some(&config), &mut environment);

        assert!(environment.is_empty());
        assert!(!supports_provider_endpoint(ProviderId::Zai));
        assert!(supports_provider_endpoint(ProviderId::LiteLlm));
    }

    #[test]
    fn projects_zai_and_copilot_typed_options_below_explicit_environment() {
        let mut zai = route(ProviderId::Zai, "default", "https://unused.example");
        zai.options.region = Some("bigmodel-cn".to_owned());
        zai.options.organization = Some("organization".to_owned());
        zai.options.project = Some("project".to_owned());
        let mut copilot = route(ProviderId::Copilot, "default", "https://unused.example");
        copilot.options.enterprise_host = Some("github.example.test".to_owned());
        copilot.options.extras_enabled = Some(true);
        copilot.options.cookie_source = Some(ProviderCookieSource::Manual);
        let config = config(vec![zai, copilot]);
        let mut environment = BTreeMap::from([("Z_AI_REGION".to_owned(), "global".to_owned())]);

        apply_provider_route_environment(Some(&config), &mut environment);

        assert_eq!(
            environment.get("Z_AI_REGION").map(String::as_str),
            Some("global")
        );
        assert_eq!(
            environment.get("Z_AI_USAGE_SCOPE").map(String::as_str),
            Some("team")
        );
        assert_eq!(
            environment.get("Z_AI_ORGANIZATION").map(String::as_str),
            Some("organization")
        );
        assert_eq!(
            environment
                .get("OMARCHY_AI_BAR_COPILOT_ENTERPRISE_HOST")
                .map(String::as_str),
            Some("github.example.test")
        );
        assert_eq!(
            environment
                .get("OMARCHY_AI_BAR_COPILOT_BUDGET_EXTRAS")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            environment
                .get("OMARCHY_AI_BAR_COPILOT_BUDGET_COOKIE_SOURCE")
                .map(String::as_str),
            Some("manual")
        );
    }

    #[test]
    fn projects_grok_source_plan_without_projecting_a_cookie_value() {
        let mut grok = route(ProviderId::Grok, "default", "https://unused.example");
        grok.options.source = Some(ProviderSourceMode::Web);
        grok.options.cookie_source = Some(ProviderCookieSource::Manual);
        let config = config(vec![grok]);
        let mut environment = BTreeMap::new();

        apply_provider_route_environment(Some(&config), &mut environment);

        assert_eq!(
            environment
                .get("OMARCHY_AI_BAR_GROK_USAGE_SOURCE")
                .map(String::as_str),
            Some("web")
        );
        assert_eq!(
            environment
                .get("OMARCHY_AI_BAR_GROK_COOKIE_SOURCE")
                .map(String::as_str),
            Some("manual")
        );
        assert!(!environment.contains_key("OMARCHY_AI_BAR_GROK_COOKIE"));
    }

    #[test]
    fn exposes_only_typed_default_route_source_and_boolean_extension() {
        let mut codex = route(ProviderId::Codex, "default", "https://unused.example");
        codex.options.source = Some(ProviderSourceMode::Pat);
        codex.options.extensions.insert(
            "external_oauth_sources".to_owned(),
            ProviderOptionValue::Boolean(true),
        );
        let mut nondefault = route(ProviderId::Codex, "work", "https://unused.example");
        nondefault.options.source = Some(ProviderSourceMode::Cli);
        let config = config(vec![codex, nondefault]);

        assert_eq!(
            provider_source(Some(&config), ProviderId::Codex),
            Some(ProviderSourceMode::Pat)
        );
        assert_eq!(
            provider_toggle(Some(&config), ProviderId::Codex, "external_oauth_sources"),
            Some(true)
        );
        assert_eq!(
            provider_toggle(Some(&config), ProviderId::Codex, "missing"),
            None
        );
    }
}
