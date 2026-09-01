//! Public-safe, value-free provider settings metadata.
//!
//! The descriptors in this module describe which controls a UI may render and
//! which closed configuration operation each control represents. They never
//! contain a selected value, credential, raw URL, environment key, or file
//! path. Runtime state is represented only by typed dependencies and hints.

use oab_domain::ProviderId;
use serde::{Serialize, Serializer};

macro_rules! closed_string_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $wire:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Stable public wire identifier.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

closed_string_enum! {
    /// Stable identity for one provider settings control.
    pub enum ProviderSettingId {
        CodexUsageSource => "codex-usage-source",
        CodexCookieSource => "codex-cookie-source",
        CodexCookieHeader => "codex-cookie-header",
        CodexLocalSessionCostLedger => "codex-local-session-cost-ledger",
        CodexHistoricalTracking => "codex-historical-tracking",
        CodexSparkUsageVisible => "codex-spark-usage-visible",
        CodexOpenAiWebExtras => "codex-openai-web-extras",
        CodexExternalOauthSources => "codex-external-oauth-sources",
        CodexOpenAiWebBatterySaver => "codex-openai-web-battery-saver",
        ClaudeUsageSource => "claude-usage-source",
        ClaudeKeychainPromptPolicy => "claude-keychain-prompt-policy",
        ClaudeCookieSource => "claude-cookie-source",
        ClaudeAdminApiKey => "claude-admin-api-key",
        ClaudeSwapExecutablePath => "claude-swap-executable-path",
        ClaudeModelScopedWeeklyUsageVisible => "claude-model-scoped-weekly-usage-visible",
        ClaudeDailyRoutinesUsageVisible => "claude-daily-routines-usage-visible",
        ClaudeOauthDirectKeychainRead => "claude-oauth-direct-keychain-read",
        ClaudeOauthPromptFreeCredentials => "claude-oauth-prompt-free-credentials",
        ClaudeSwapAccounts => "claude-swap-accounts",
        ClaudeSwapShowSingleAccount => "claude-swap-show-single-account",
        GrokUsageSource => "grok-usage-source",
        GrokCookieSource => "grok-cookie-source",
        GrokCookieHeader => "grok-cookie",
        CopilotIconSecondaryWindow => "copilot-icon-secondary-window",
        CopilotBudgetCookieSource => "copilot-budget-cookie-source",
        CopilotBudgetCookieHeader => "copilot-budget-cookie-header",
        CopilotEnterpriseHost => "copilot-enterprise-host",
        CopilotBudgetExtras => "copilot-budget-extras",
        ZaiApiRegion => "zai-api-region",
        ZaiApiKey => "zai-api-key"
    }
}

closed_string_enum! {
    /// Closed value vocabulary for picker options and dependency predicates.
    pub enum ProviderSettingChoice {
        Auto => "auto",
        Pat => "pat",
        Oauth => "oauth",
        Cli => "cli",
        Api => "api",
        Web => "web",
        Manual => "manual",
        Off => "off",
        Never => "never",
        OnlyOnUserAction => "onlyOnUserAction",
        Always => "always",
        Global => "global",
        BigModelCn => "bigmodel-cn",
        Chat => "chat"
    }
}

closed_string_enum! {
    /// Logical secret destination. A slot identifies storage without carrying a value.
    pub enum ProviderSecretSlot {
        CodexWebCookie => "codex-web-cookie",
        ClaudeAdminApiKey => "claude-admin-api-key",
        GrokWebCookie => "grok-web-cookie",
        CopilotBudgetCookie => "copilot-budget-cookie",
        ZaiApiKey => "zai-api-key"
    }
}

closed_string_enum! {
    /// Stable identity for one provider action.
    pub enum ProviderSettingsActionId {
        AddCodexAccount => "add-codex-account",
        OpenGrokUsage => "grok-open-usage",
        OpenGrokTokenFile => "grok-open-token-file",
        RefreshCopilotBudgets => "refresh-copilot-budget-cookie",
        AddCopilotAccount => "copilot-add-account-action",
        OpenZaiApiKeys => "zai-open-api-keys"
    }
}

closed_string_enum! {
    /// Explicit reason why upstream metadata is not actionable in this runtime.
    pub enum ProviderSettingsGap {
        ConfigurableCostLedger => "configurable-cost-ledger",
        ConfigurableHistoryTracking => "configurable-history-tracking",
        DisplayFiltering => "display-filtering",
        OpenAiWebExtras => "openai-web-extras",
        ManagedAccountLifecycle => "managed-account-lifecycle",
        DesktopWidgets => "desktop-widgets",
        MacOsKeychainPolicy => "macos-keychain-policy",
        ClaudeSwap => "claude-swap",
        ClaudeAdminApi => "claude-admin-api",
        ClaudeSourceSelection => "claude-source-selection",
        ClaudeWebUsage => "claude-web-usage",
        ClaudeCliUsage => "claude-cli-usage",
        BrowserCookieUsage => "browser-cookie-usage",
        ExplicitGrokSourceSelection => "explicit-grok-source-selection",
        CopilotBudgetConfiguration => "copilot-budget-configuration",
        CopilotEnterpriseLogin => "copilot-enterprise-login",
        MenuBarMetricSelection => "menu-bar-metric-selection",
        RegionalCredentialPageAction => "regional-credential-page-action",
        ProviderOwnedFileAction => "provider-owned-file-action",
        MultiAccountLifecycle => "multi-account-lifecycle"
    }
}

closed_string_enum! {
    /// Global, non-provider setting referenced by a dependency expression.
    pub enum ProviderSettingsFeature {
        OptionalCreditsAndExtraUsage => "optional-credits-and-extra-usage",
        KeychainAccess => "keychain-access"
    }
}

closed_string_enum! {
    /// Public runtime fact that a UI may use to resolve a static dependency.
    pub enum ProviderSettingsRuntimeFact {
        ConfiguredAccountsPresent => "configured-accounts-present"
    }
}

closed_string_enum! {
    /// Typed dynamic annotation requested by otherwise-static metadata.
    pub enum ProviderSettingsRuntimeHint {
        ResolvedSource => "resolved-source",
        ImportedBrowserSession => "imported-browser-session",
        ClaudeKeychainPolicy => "claude-keychain-policy",
        ClaudeSwapStatus => "claude-swap-status",
        CopilotBudgetStatus => "copilot-budget-status",
        CopilotBudgetOptions => "copilot-budget-options"
    }
}

/// Whether one descriptor is safe for an interactive UI in the current runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderSettingsAvailability {
    /// The providers crate has a matching typed runtime behavior.
    Implemented,
    /// Metadata is retained for parity, but selecting it would currently be ignored.
    Unavailable {
        /// Closed parity gap that must be resolved before enabling the item.
        gap: ProviderSettingsGap,
    },
}

impl ProviderSettingsAvailability {
    /// Whether a UI may expose the item as interactive.
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        matches!(self, Self::Implemented)
    }
}

/// Closed boolean expression for visibility and enabled-state dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "condition", rename_all = "snake_case")]
pub enum ProviderSettingsCondition {
    /// No dependency.
    Always,
    /// Every nested condition must match.
    All {
        /// Static bounded operands.
        conditions: &'static [Self],
    },
    /// At least one nested condition must match.
    Any {
        /// Static bounded operands.
        conditions: &'static [Self],
    },
    /// A picker must have one exact closed choice.
    Choice {
        /// Referenced picker.
        setting: ProviderSettingId,
        /// Required choice.
        choice: ProviderSettingChoice,
    },
    /// A toggle must match the requested state.
    Toggle {
        /// Referenced toggle.
        setting: ProviderSettingId,
        /// Required toggle state.
        enabled: bool,
    },
    /// An application-wide feature must match the requested state.
    Feature {
        /// Referenced feature.
        feature: ProviderSettingsFeature,
        /// Required feature state.
        enabled: bool,
    },
    /// A bounded public runtime fact must be true.
    RuntimeFact {
        /// Referenced fact.
        fact: ProviderSettingsRuntimeFact,
    },
}

/// Group in which a generic settings UI should place a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSettingsSection {
    /// Menu-bar presentation choices.
    MenuBar,
    /// Source and connection choices.
    Connection,
    /// Credential or other provider input.
    Credentials,
    /// Optional provider behavior.
    Options,
}

/// Public metadata shared by every settings control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsItemMetadata {
    /// Stable control identity.
    pub id: ProviderSettingId,
    /// User-facing title.
    pub title: &'static str,
    /// User-facing explanatory text.
    pub subtitle: &'static str,
    /// Shared UI group.
    pub section: ProviderSettingsSection,
    /// Static visibility expression.
    pub visible_when: ProviderSettingsCondition,
    /// Static enabled-state expression.
    pub enabled_when: ProviderSettingsCondition,
    /// Runtime implementation state.
    pub availability: ProviderSettingsAvailability,
    /// Optional request for public dynamic annotation text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_hint: Option<ProviderSettingsRuntimeHint>,
}

/// One closed picker option. No selected or default value is stored here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsPickerOption {
    /// Persisted closed choice.
    pub choice: ProviderSettingChoice,
    /// User-facing label.
    pub title: &'static str,
    /// Whether choosing this option has a matching runtime path.
    pub availability: ProviderSettingsAvailability,
}

/// Runtime-owned option expansion for a picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSettingsDynamicOptions {
    /// Named Copilot budget windows discovered in the latest sample.
    CopilotBudgetWindows,
}

/// Static picker metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsPickerDescriptor {
    /// Shared control metadata.
    #[serde(flatten)]
    pub item: ProviderSettingsItemMetadata,
    /// Closed static choices.
    pub options: &'static [ProviderSettingsPickerOption],
    /// Optional safe runtime option source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_options: Option<ProviderSettingsDynamicOptions>,
    /// Actions placed beside the picker.
    pub actions: &'static [ProviderSettingsActionId],
}

/// Static toggle metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsToggleDescriptor {
    /// Shared control metadata.
    #[serde(flatten)]
    pub item: ProviderSettingsItemMetadata,
    /// Actions shown only while the toggle is enabled.
    pub actions: &'static [ProviderSettingsActionId],
}

/// Static non-secret text option metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsPlainOptionDescriptor {
    /// Shared control metadata.
    #[serde(flatten)]
    pub item: ProviderSettingsItemMetadata,
    /// Public placeholder, never a stored value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<&'static str>,
    /// Actions placed below the option.
    pub actions: &'static [ProviderSettingsActionId],
}

/// Static secret-input metadata. The secret itself is deliberately unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsSecretSlotDescriptor {
    /// Shared control metadata.
    #[serde(flatten)]
    pub item: ProviderSettingsItemMetadata,
    /// Closed managed-secret destination.
    pub slot: ProviderSecretSlot,
    /// Public format hint, never credential content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<&'static str>,
    /// Actions placed below the secret input.
    pub actions: &'static [ProviderSettingsActionId],
}

/// One heterogeneous provider control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "descriptor", rename_all = "snake_case")]
pub enum ProviderSettingsControlDescriptor {
    /// Choice picker.
    Picker(ProviderSettingsPickerDescriptor),
    /// Boolean toggle.
    Toggle(ProviderSettingsToggleDescriptor),
    /// Non-secret text option.
    PlainOption(ProviderSettingsPlainOptionDescriptor),
    /// Managed secret input.
    SecretSlot(ProviderSettingsSecretSlotDescriptor),
}

impl ProviderSettingsControlDescriptor {
    /// Shared item metadata, independent of control kind.
    #[must_use]
    pub const fn item(self) -> ProviderSettingsItemMetadata {
        match self {
            Self::Picker(descriptor) => descriptor.item,
            Self::Toggle(descriptor) => descriptor.item,
            Self::PlainOption(descriptor) => descriptor.item,
            Self::SecretSlot(descriptor) => descriptor.item,
        }
    }

    /// Whether the whole control has a matching runtime path.
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        self.item().availability.is_implemented()
    }
}

/// Shared visual treatment for provider actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSettingsActionStyle {
    /// Compact bordered button.
    Bordered,
    /// Link-style action.
    Link,
}

/// Closed side effect requested by a provider settings action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSettingsActionTarget {
    /// Launch the provider's login flow.
    Login,
    /// Launch the provider's managed-account flow.
    AddManagedAccount,
    /// Open the provider usage dashboard selected by application policy.
    OpenUsageDashboard,
    /// Open the provider-owned token file selected by application policy.
    OpenTokenFile,
    /// Refresh the provider without changing credentials.
    RefreshProvider,
    /// Open the credential page selected from the current region.
    OpenRegionalCredentialPage,
}

/// Static provider action metadata without closures, commands, or raw URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsActionDescriptor {
    /// Stable action identity.
    pub id: ProviderSettingsActionId,
    /// User-facing title.
    pub title: &'static str,
    /// Shared visual treatment.
    pub style: ProviderSettingsActionStyle,
    /// Shared UI group when the action is rendered as its own row.
    pub section: ProviderSettingsSection,
    /// Whether the action is rendered independently of a control or account editor.
    pub standalone: bool,
    /// Closed application-owned side effect.
    pub target: ProviderSettingsActionTarget,
    /// Static visibility expression.
    pub visible_when: ProviderSettingsCondition,
    /// Runtime implementation state.
    pub availability: ProviderSettingsAvailability,
}

/// Credential kinds accepted by the shared account editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAccountCredentialKind {
    /// Application-managed provider OAuth identity.
    Oauth,
    /// Provider personal access token.
    PersonalAccessToken,
    /// Browser session cookie or full Cookie header.
    WebSession,
    /// Organization administrator API key.
    AdminApiKey,
    /// Provider API key.
    ApiKey,
    /// `SuperGrok` bearer credential.
    GrokBearer,
}

/// Input requirement for an optional account-scoping field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAccountFieldMode {
    /// Field is not shown.
    Hidden,
    /// Field is optional for every account.
    Optional,
    /// Field is required only when team mode is selected.
    RequiredInTeamMode,
}

/// Static shared-account editor metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderAccountSupportDescriptor {
    /// User-facing section title.
    pub title: &'static str,
    /// User-facing explanatory text.
    pub subtitle: &'static str,
    /// Public credential-format hint.
    pub placeholder: &'static str,
    /// Closed credential kinds accepted by the upstream account model.
    pub credential_kinds: &'static [ProviderAccountCredentialKind],
    /// Organization field behavior.
    pub organization_field: ProviderAccountFieldMode,
    /// Workspace or project field behavior.
    pub workspace_field: ProviderAccountFieldMode,
    /// Whether selecting an account requires the manual-cookie source.
    pub requires_manual_cookie_source: bool,
    /// Primary action shown by the shared account editor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_action: Option<ProviderSettingsActionId>,
    /// Optional provider-owned token-file action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_file_action: Option<ProviderSettingsActionId>,
    /// Static visibility expression.
    pub visible_when: ProviderSettingsCondition,
    /// Runtime implementation state.
    pub availability: ProviderSettingsAvailability,
}

/// Complete value-free settings schema for one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderSettingsDescriptor {
    /// Descriptor schema version.
    pub schema_version: u8,
    /// Provider owning every control, action, and account operation.
    pub provider: ProviderId,
    /// Static controls in stable upstream order.
    pub controls: &'static [ProviderSettingsControlDescriptor],
    /// Static action catalog referenced by controls and account support.
    pub actions: &'static [ProviderSettingsActionDescriptor],
    /// Optional shared account-editor metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<ProviderAccountSupportDescriptor>,
}

impl ProviderSettingsDescriptor {
    /// Finds one control by its stable closed identity.
    #[must_use]
    pub fn control(&self, id: ProviderSettingId) -> Option<&ProviderSettingsControlDescriptor> {
        self.controls.iter().find(|control| control.item().id == id)
    }

    /// Finds one action by its stable closed identity.
    #[must_use]
    pub fn action(
        &self,
        id: ProviderSettingsActionId,
    ) -> Option<&ProviderSettingsActionDescriptor> {
        self.actions.iter().find(|action| action.id == id)
    }
}

const IMPLEMENTED: ProviderSettingsAvailability = ProviderSettingsAvailability::Implemented;
const ALWAYS: ProviderSettingsCondition = ProviderSettingsCondition::Always;
const NO_ACTIONS: &[ProviderSettingsActionId] = &[];

const fn unavailable(gap: ProviderSettingsGap) -> ProviderSettingsAvailability {
    ProviderSettingsAvailability::Unavailable { gap }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the constructor keeps each static control declaration auditable in one place"
)]
const fn item(
    id: ProviderSettingId,
    title: &'static str,
    subtitle: &'static str,
    section: ProviderSettingsSection,
    visible_when: ProviderSettingsCondition,
    enabled_when: ProviderSettingsCondition,
    availability: ProviderSettingsAvailability,
    runtime_hint: Option<ProviderSettingsRuntimeHint>,
) -> ProviderSettingsItemMetadata {
    ProviderSettingsItemMetadata {
        id,
        title,
        subtitle,
        section,
        visible_when,
        enabled_when,
        availability,
        runtime_hint,
    }
}

const fn option(
    choice: ProviderSettingChoice,
    title: &'static str,
    availability: ProviderSettingsAvailability,
) -> ProviderSettingsPickerOption {
    ProviderSettingsPickerOption {
        choice,
        title,
        availability,
    }
}

const CODEX_WEB_EXTRAS_ON: ProviderSettingsCondition = ProviderSettingsCondition::Toggle {
    setting: ProviderSettingId::CodexOpenAiWebExtras,
    enabled: true,
};
const CODEX_COOKIE_MANUAL: ProviderSettingsCondition = ProviderSettingsCondition::Choice {
    setting: ProviderSettingId::CodexCookieSource,
    choice: ProviderSettingChoice::Manual,
};
const OPTIONAL_EXTRAS_ON: ProviderSettingsCondition = ProviderSettingsCondition::Feature {
    feature: ProviderSettingsFeature::OptionalCreditsAndExtraUsage,
    enabled: true,
};

const CODEX_USAGE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(ProviderSettingChoice::Auto, "Auto", IMPLEMENTED),
    option(ProviderSettingChoice::Pat, "PAT", IMPLEMENTED),
    option(ProviderSettingChoice::Oauth, "OAuth API", IMPLEMENTED),
    option(ProviderSettingChoice::Cli, "CLI (RPC/PTY)", IMPLEMENTED),
];
const CODEX_WEB_UNAVAILABLE: ProviderSettingsAvailability =
    unavailable(ProviderSettingsGap::OpenAiWebExtras);
const CODEX_COOKIE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(ProviderSettingChoice::Auto, "Auto", CODEX_WEB_UNAVAILABLE),
    option(
        ProviderSettingChoice::Manual,
        "Manual",
        CODEX_WEB_UNAVAILABLE,
    ),
    option(ProviderSettingChoice::Off, "Off", CODEX_WEB_UNAVAILABLE),
];

const CODEX_CONTROLS: &[ProviderSettingsControlDescriptor] = &[
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CodexLocalSessionCostLedger,
            "Local session cost estimates",
            concat!(
                "Uses this machine's Codex sessions instead of the selected managed account's ",
                "session history. Works with organization API keys and uses locally cached or ",
                "bundled model prices without making a network request."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            unavailable(ProviderSettingsGap::ConfigurableCostLedger),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CodexHistoricalTracking,
            "Historical tracking",
            "Stores local Codex usage history to personalize pace predictions.",
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            unavailable(ProviderSettingsGap::ConfigurableHistoryTracking),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CodexSparkUsageVisible,
            "Show Codex Spark usage",
            concat!(
                "Shows Codex Spark quota rows in the menu and provider preview. ",
                "Requires optional credits and extra usage in Display settings."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            OPTIONAL_EXTRAS_ON,
            unavailable(ProviderSettingsGap::DisplayFiltering),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CodexOpenAiWebExtras,
            "OpenAI web extras",
            concat!(
                "Optional. Turn this on to show code review, usage breakdown, and credits history ",
                "through chatgpt.com."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            CODEX_WEB_UNAVAILABLE,
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CodexExternalOauthSources,
            "External Codex OAuth sources",
            concat!(
                "Explicitly allow read-only fallback to legacy Codex and OpenCode OAuth files. ",
                "Omarchy AI Bar never refreshes or writes those external credentials."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CodexOpenAiWebBatterySaver,
            "OpenAI web battery saver",
            concat!(
                "Limits background chatgpt.com refreshes to reduce battery and network usage. ",
                "Dashboard extras may stay stale until manually refreshed."
            ),
            ProviderSettingsSection::Options,
            CODEX_WEB_EXTRAS_ON,
            ALWAYS,
            CODEX_WEB_UNAVAILABLE,
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::CodexUsageSource,
            "Quota usage source",
            concat!(
                "Controls live session and weekly quota fetching only. ",
                "Local session cost estimates work independently."
            ),
            ProviderSettingsSection::Connection,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            Some(ProviderSettingsRuntimeHint::ResolvedSource),
        ),
        options: CODEX_USAGE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::CodexCookieSource,
            "OpenAI cookies",
            "Automatic imports browser cookies for dashboard extras.",
            ProviderSettingsSection::Connection,
            CODEX_WEB_EXTRAS_ON,
            ALWAYS,
            CODEX_WEB_UNAVAILABLE,
            Some(ProviderSettingsRuntimeHint::ImportedBrowserSession),
        ),
        options: CODEX_COOKIE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::SecretSlot(ProviderSettingsSecretSlotDescriptor {
        item: item(
            ProviderSettingId::CodexCookieHeader,
            "",
            "",
            ProviderSettingsSection::Credentials,
            CODEX_COOKIE_MANUAL,
            ALWAYS,
            CODEX_WEB_UNAVAILABLE,
            None,
        ),
        slot: ProviderSecretSlot::CodexWebCookie,
        placeholder: Some("Cookie: …"),
        actions: NO_ACTIONS,
    }),
];

const CODEX_ACTIONS: &[ProviderSettingsActionDescriptor] = &[ProviderSettingsActionDescriptor {
    id: ProviderSettingsActionId::AddCodexAccount,
    title: "Add Account",
    style: ProviderSettingsActionStyle::Bordered,
    section: ProviderSettingsSection::Connection,
    standalone: false,
    target: ProviderSettingsActionTarget::AddManagedAccount,
    visible_when: ALWAYS,
    availability: unavailable(ProviderSettingsGap::ManagedAccountLifecycle),
}];

const CODEX_ACCOUNT_CREDENTIALS: &[ProviderAccountCredentialKind] =
    &[ProviderAccountCredentialKind::Oauth];
const CODEX_ACCOUNTS: ProviderAccountSupportDescriptor = ProviderAccountSupportDescriptor {
    title: "Codex accounts",
    subtitle: "Add and switch application-managed Codex OAuth accounts.",
    placeholder: "Sign in with Codex OAuth…",
    credential_kinds: CODEX_ACCOUNT_CREDENTIALS,
    organization_field: ProviderAccountFieldMode::Hidden,
    workspace_field: ProviderAccountFieldMode::Hidden,
    requires_manual_cookie_source: false,
    primary_action: Some(ProviderSettingsActionId::AddCodexAccount),
    token_file_action: None,
    visible_when: ALWAYS,
    availability: unavailable(ProviderSettingsGap::ManagedAccountLifecycle),
};

const CODEX_SETTINGS: ProviderSettingsDescriptor = ProviderSettingsDescriptor {
    schema_version: 1,
    provider: ProviderId::Codex,
    controls: CODEX_CONTROLS,
    actions: CODEX_ACTIONS,
    accounts: Some(CODEX_ACCOUNTS),
};

const KEYCHAIN_ACCESS_ON: ProviderSettingsCondition = ProviderSettingsCondition::Feature {
    feature: ProviderSettingsFeature::KeychainAccess,
    enabled: true,
};
const CLAUDE_SWAP_ON: ProviderSettingsCondition = ProviderSettingsCondition::Toggle {
    setting: ProviderSettingId::ClaudeSwapAccounts,
    enabled: true,
};
const CLAUDE_COOKIE_MANUAL: ProviderSettingsCondition = ProviderSettingsCondition::Choice {
    setting: ProviderSettingId::ClaudeCookieSource,
    choice: ProviderSettingChoice::Manual,
};
const CLAUDE_ACCOUNT_VISIBILITY_OPERANDS: &[ProviderSettingsCondition] = &[
    ProviderSettingsCondition::RuntimeFact {
        fact: ProviderSettingsRuntimeFact::ConfiguredAccountsPresent,
    },
    CLAUDE_COOKIE_MANUAL,
];
const CLAUDE_ACCOUNTS_VISIBLE: ProviderSettingsCondition = ProviderSettingsCondition::Any {
    conditions: CLAUDE_ACCOUNT_VISIBILITY_OPERANDS,
};

const CLAUDE_USAGE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(ProviderSettingChoice::Auto, "Auto", IMPLEMENTED),
    option(
        ProviderSettingChoice::Api,
        "API (Admin key)",
        unavailable(ProviderSettingsGap::ClaudeAdminApi),
    ),
    option(ProviderSettingChoice::Oauth, "OAuth API", IMPLEMENTED),
    option(
        ProviderSettingChoice::Web,
        "Web API (cookies)",
        unavailable(ProviderSettingsGap::ClaudeWebUsage),
    ),
    option(ProviderSettingChoice::Cli, "CLI", IMPLEMENTED),
];
const CLAUDE_KEYCHAIN_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(
        ProviderSettingChoice::Never,
        "Never prompt",
        unavailable(ProviderSettingsGap::MacOsKeychainPolicy),
    ),
    option(
        ProviderSettingChoice::OnlyOnUserAction,
        "Only on user action",
        unavailable(ProviderSettingsGap::MacOsKeychainPolicy),
    ),
    option(
        ProviderSettingChoice::Always,
        "Always allow prompts",
        unavailable(ProviderSettingsGap::MacOsKeychainPolicy),
    ),
];
const CLAUDE_COOKIE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(
        ProviderSettingChoice::Auto,
        "Auto",
        unavailable(ProviderSettingsGap::ClaudeWebUsage),
    ),
    option(
        ProviderSettingChoice::Manual,
        "Manual",
        unavailable(ProviderSettingsGap::ClaudeWebUsage),
    ),
];

const CLAUDE_CONTROLS: &[ProviderSettingsControlDescriptor] = &[
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::ClaudeModelScopedWeeklyUsageVisible,
            "Show model-specific weekly usage in widgets",
            "Shows model-specific Claude quotas, such as Fable, in desktop widgets.",
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            unavailable(ProviderSettingsGap::DesktopWidgets),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::ClaudeDailyRoutinesUsageVisible,
            "Show Daily Routines usage",
            concat!(
                "Shows the Daily Routines quota row in the menu and provider preview. ",
                "Requires optional credits and extra usage in Display settings."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            OPTIONAL_EXTRAS_ON,
            unavailable(ProviderSettingsGap::DisplayFiltering),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::ClaudeOauthDirectKeychainRead,
            "Allow reading Claude Code's credentials",
            concat!(
                "Reads Claude Code's Keychain item for OAuth usage; macOS may ask for permission. ",
                "This policy is not applicable to the Linux credential-file reader."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            KEYCHAIN_ACCESS_ON,
            unavailable(ProviderSettingsGap::MacOsKeychainPolicy),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::ClaudeOauthPromptFreeCredentials,
            "Avoid Keychain prompts",
            "Never allow Claude OAuth credential reads to show macOS Keychain prompts.",
            ProviderSettingsSection::Options,
            ALWAYS,
            KEYCHAIN_ACCESS_ON,
            unavailable(ProviderSettingsGap::MacOsKeychainPolicy),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::ClaudeSwapAccounts,
            "Read accounts from claude-swap",
            concat!(
                "Shows usage and lets you switch accounts through `cswap`. Credentials stay ",
                "managed by claude-swap; Omarchy AI Bar never reads them."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            unavailable(ProviderSettingsGap::ClaudeSwap),
            Some(ProviderSettingsRuntimeHint::ClaudeSwapStatus),
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::ClaudeSwapShowSingleAccount,
            "Show account card when only one account is available",
            "Prefer claude-swap over the ambient Claude account presentation.",
            ProviderSettingsSection::Options,
            CLAUDE_SWAP_ON,
            ALWAYS,
            unavailable(ProviderSettingsGap::ClaudeSwap),
            None,
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::ClaudeUsageSource,
            "Usage source",
            "Auto falls back to the next source if the preferred one fails.",
            ProviderSettingsSection::Connection,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            Some(ProviderSettingsRuntimeHint::ResolvedSource),
        ),
        options: CLAUDE_USAGE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::ClaudeKeychainPromptPolicy,
            "Keychain prompt policy",
            "Controls when Claude OAuth may ask macOS for Keychain access.",
            ProviderSettingsSection::Connection,
            ALWAYS,
            KEYCHAIN_ACCESS_ON,
            unavailable(ProviderSettingsGap::MacOsKeychainPolicy),
            Some(ProviderSettingsRuntimeHint::ClaudeKeychainPolicy),
        ),
        options: CLAUDE_KEYCHAIN_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::ClaudeCookieSource,
            "Claude cookies",
            "Automatic imports browser cookies for the web API.",
            ProviderSettingsSection::Connection,
            ALWAYS,
            ALWAYS,
            unavailable(ProviderSettingsGap::ClaudeWebUsage),
            Some(ProviderSettingsRuntimeHint::ImportedBrowserSession),
        ),
        options: CLAUDE_COOKIE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::SecretSlot(ProviderSettingsSecretSlotDescriptor {
        item: item(
            ProviderSettingId::ClaudeAdminApiKey,
            "Admin API key",
            "Requires an Anthropic Admin API key.",
            ProviderSettingsSection::Credentials,
            ALWAYS,
            ALWAYS,
            unavailable(ProviderSettingsGap::ClaudeAdminApi),
            None,
        ),
        slot: ProviderSecretSlot::ClaudeAdminApiKey,
        placeholder: Some("sk-ant-admin..."),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::PlainOption(ProviderSettingsPlainOptionDescriptor {
        item: item(
            ProviderSettingId::ClaudeSwapExecutablePath,
            "claude-swap executable",
            "Path to the cswap executable (github.com/realiti4/claude-swap).",
            ProviderSettingsSection::Credentials,
            CLAUDE_SWAP_ON,
            ALWAYS,
            unavailable(ProviderSettingsGap::ClaudeSwap),
            None,
        ),
        placeholder: Some("~/.local/bin/cswap"),
        actions: NO_ACTIONS,
    }),
];

const CLAUDE_ACTIONS: &[ProviderSettingsActionDescriptor] = &[];

const CLAUDE_ACCOUNT_CREDENTIALS: &[ProviderAccountCredentialKind] = &[
    ProviderAccountCredentialKind::WebSession,
    ProviderAccountCredentialKind::Oauth,
    ProviderAccountCredentialKind::AdminApiKey,
];
const CLAUDE_ACCOUNTS: ProviderAccountSupportDescriptor = ProviderAccountSupportDescriptor {
    title: "Claude credentials",
    subtitle: "Store Claude sessionKey cookies, OAuth tokens, or Anthropic Admin API keys.",
    placeholder: "Paste sessionKey, OAuth token, or sk-ant-admin…",
    credential_kinds: CLAUDE_ACCOUNT_CREDENTIALS,
    organization_field: ProviderAccountFieldMode::Optional,
    workspace_field: ProviderAccountFieldMode::Hidden,
    requires_manual_cookie_source: true,
    primary_action: None,
    token_file_action: None,
    visible_when: CLAUDE_ACCOUNTS_VISIBLE,
    availability: unavailable(ProviderSettingsGap::MultiAccountLifecycle),
};

const CLAUDE_SETTINGS: ProviderSettingsDescriptor = ProviderSettingsDescriptor {
    schema_version: 1,
    provider: ProviderId::Claude,
    controls: CLAUDE_CONTROLS,
    actions: CLAUDE_ACTIONS,
    accounts: Some(CLAUDE_ACCOUNTS),
};

const GROK_SOURCE_AUTO: ProviderSettingsCondition = ProviderSettingsCondition::Choice {
    setting: ProviderSettingId::GrokUsageSource,
    choice: ProviderSettingChoice::Auto,
};
const GROK_SOURCE_WEB: ProviderSettingsCondition = ProviderSettingsCondition::Choice {
    setting: ProviderSettingId::GrokUsageSource,
    choice: ProviderSettingChoice::Web,
};
const GROK_COOKIE_SOURCE_VISIBILITY_OPERANDS: &[ProviderSettingsCondition] =
    &[GROK_SOURCE_AUTO, GROK_SOURCE_WEB];
const GROK_COOKIE_SOURCE_VISIBLE: ProviderSettingsCondition = ProviderSettingsCondition::Any {
    conditions: GROK_COOKIE_SOURCE_VISIBILITY_OPERANDS,
};
const GROK_COOKIE_MANUAL: ProviderSettingsCondition = ProviderSettingsCondition::Choice {
    setting: ProviderSettingId::GrokCookieSource,
    choice: ProviderSettingChoice::Manual,
};
const GROK_COOKIE_HEADER_VISIBILITY_OPERANDS: &[ProviderSettingsCondition] =
    &[GROK_COOKIE_SOURCE_VISIBLE, GROK_COOKIE_MANUAL];
const GROK_COOKIE_HEADER_VISIBLE: ProviderSettingsCondition = ProviderSettingsCondition::All {
    conditions: GROK_COOKIE_HEADER_VISIBILITY_OPERANDS,
};

const GROK_USAGE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(ProviderSettingChoice::Auto, "Auto", IMPLEMENTED),
    option(ProviderSettingChoice::Cli, "Grok CLI", IMPLEMENTED),
    option(ProviderSettingChoice::Oauth, "SuperGrok OAuth", IMPLEMENTED),
    option(ProviderSettingChoice::Web, "Browser cookies", IMPLEMENTED),
];
const GROK_COOKIE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(ProviderSettingChoice::Auto, "Auto", IMPLEMENTED),
    option(ProviderSettingChoice::Manual, "Manual", IMPLEMENTED),
    option(ProviderSettingChoice::Off, "Off", IMPLEMENTED),
];
const GROK_OPEN_USAGE_ACTION: &[ProviderSettingsActionId] =
    &[ProviderSettingsActionId::OpenGrokUsage];

const GROK_CONTROLS: &[ProviderSettingsControlDescriptor] = &[
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::GrokUsageSource,
            "Usage source",
            concat!(
                "Auto tries the Grok CLI, read-only SuperGrok OAuth billing proxy, then an enabled ",
                "manual or isolated Linux browser session. Bearer gRPC enrichment remains disabled."
            ),
            ProviderSettingsSection::Connection,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            Some(ProviderSettingsRuntimeHint::ResolvedSource),
        ),
        options: GROK_USAGE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::GrokCookieSource,
            "Cookie source",
            "Automatic imports isolated grok.com sessions from supported Linux browser profiles.",
            ProviderSettingsSection::Connection,
            GROK_COOKIE_SOURCE_VISIBLE,
            ALWAYS,
            IMPLEMENTED,
            Some(ProviderSettingsRuntimeHint::ImportedBrowserSession),
        ),
        options: GROK_COOKIE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::SecretSlot(ProviderSettingsSecretSlotDescriptor {
        item: item(
            ProviderSettingId::GrokCookieHeader,
            "",
            "",
            ProviderSettingsSection::Credentials,
            GROK_COOKIE_HEADER_VISIBLE,
            ALWAYS,
            IMPLEMENTED,
            None,
        ),
        slot: ProviderSecretSlot::GrokWebCookie,
        placeholder: Some("Cookie: …"),
        actions: GROK_OPEN_USAGE_ACTION,
    }),
];

const GROK_ACTIONS: &[ProviderSettingsActionDescriptor] = &[
    ProviderSettingsActionDescriptor {
        id: ProviderSettingsActionId::OpenGrokUsage,
        title: "Open grok.com usage",
        style: ProviderSettingsActionStyle::Link,
        section: ProviderSettingsSection::Credentials,
        standalone: false,
        target: ProviderSettingsActionTarget::OpenUsageDashboard,
        visible_when: ALWAYS,
        availability: IMPLEMENTED,
    },
    ProviderSettingsActionDescriptor {
        id: ProviderSettingsActionId::OpenGrokTokenFile,
        title: "Open token file",
        style: ProviderSettingsActionStyle::Link,
        section: ProviderSettingsSection::Credentials,
        standalone: false,
        target: ProviderSettingsActionTarget::OpenTokenFile,
        visible_when: ALWAYS,
        availability: IMPLEMENTED,
    },
];

const GROK_ACCOUNT_CREDENTIALS: &[ProviderAccountCredentialKind] = &[
    ProviderAccountCredentialKind::GrokBearer,
    ProviderAccountCredentialKind::WebSession,
];
const GROK_ACCOUNTS: ProviderAccountSupportDescriptor = ProviderAccountSupportDescriptor {
    title: "SuperGrok tokens",
    subtitle: "Paste a SuperGrok bearer or grok.com cookie.",
    placeholder: "Bearer … or Cookie: …",
    credential_kinds: GROK_ACCOUNT_CREDENTIALS,
    organization_field: ProviderAccountFieldMode::Hidden,
    workspace_field: ProviderAccountFieldMode::Hidden,
    requires_manual_cookie_source: false,
    primary_action: None,
    token_file_action: Some(ProviderSettingsActionId::OpenGrokTokenFile),
    visible_when: ALWAYS,
    availability: unavailable(ProviderSettingsGap::MultiAccountLifecycle),
};

const GROK_SETTINGS: ProviderSettingsDescriptor = ProviderSettingsDescriptor {
    schema_version: 1,
    provider: ProviderId::Grok,
    controls: GROK_CONTROLS,
    actions: GROK_ACTIONS,
    accounts: Some(GROK_ACCOUNTS),
};

const COPILOT_BUDGET_EXTRAS_ON: ProviderSettingsCondition = ProviderSettingsCondition::Toggle {
    setting: ProviderSettingId::CopilotBudgetExtras,
    enabled: true,
};
const COPILOT_BUDGET_COOKIE_MANUAL: ProviderSettingsCondition = ProviderSettingsCondition::Choice {
    setting: ProviderSettingId::CopilotBudgetCookieSource,
    choice: ProviderSettingChoice::Manual,
};
const COPILOT_BUDGET_COOKIE_VISIBILITY_OPERANDS: &[ProviderSettingsCondition] =
    &[COPILOT_BUDGET_EXTRAS_ON, COPILOT_BUDGET_COOKIE_MANUAL];
const COPILOT_BUDGET_COOKIE_VISIBLE: ProviderSettingsCondition = ProviderSettingsCondition::All {
    conditions: COPILOT_BUDGET_COOKIE_VISIBILITY_OPERANDS,
};

const COPILOT_AUTO_BUDGET_UNAVAILABLE: ProviderSettingsAvailability =
    unavailable(ProviderSettingsGap::CopilotBudgetConfiguration);
const COPILOT_SECONDARY_OPTIONS: &[ProviderSettingsPickerOption] = &[option(
    ProviderSettingChoice::Chat,
    "Chat",
    unavailable(ProviderSettingsGap::MenuBarMetricSelection),
)];
const COPILOT_COOKIE_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(
        ProviderSettingChoice::Auto,
        "Auto",
        COPILOT_AUTO_BUDGET_UNAVAILABLE,
    ),
    option(ProviderSettingChoice::Manual, "Manual", IMPLEMENTED),
];
const COPILOT_REFRESH_BUDGET_ACTION: &[ProviderSettingsActionId] =
    &[ProviderSettingsActionId::RefreshCopilotBudgets];

const COPILOT_CONTROLS: &[ProviderSettingsControlDescriptor] = &[
    ProviderSettingsControlDescriptor::Toggle(ProviderSettingsToggleDescriptor {
        item: item(
            ProviderSettingId::CopilotBudgetExtras,
            "Budget extras",
            concat!(
                "Optional. Turn this on to fetch configured GitHub Copilot budget limits and ",
                "show them as extra bars."
            ),
            ProviderSettingsSection::Options,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            Some(ProviderSettingsRuntimeHint::CopilotBudgetStatus),
        ),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::CopilotIconSecondaryWindow,
            "Menu bar secondary metric",
            "Choose the second meter shown in the menu bar icon.",
            ProviderSettingsSection::MenuBar,
            COPILOT_BUDGET_EXTRAS_ON,
            ALWAYS,
            unavailable(ProviderSettingsGap::MenuBarMetricSelection),
            Some(ProviderSettingsRuntimeHint::CopilotBudgetOptions),
        ),
        options: COPILOT_SECONDARY_OPTIONS,
        dynamic_options: Some(ProviderSettingsDynamicOptions::CopilotBudgetWindows),
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::CopilotBudgetCookieSource,
            "GitHub cookies",
            "Use a manually stored GitHub Cookie header for optional budget extras.",
            ProviderSettingsSection::Connection,
            COPILOT_BUDGET_EXTRAS_ON,
            ALWAYS,
            IMPLEMENTED,
            Some(ProviderSettingsRuntimeHint::ImportedBrowserSession),
        ),
        options: COPILOT_COOKIE_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::SecretSlot(ProviderSettingsSecretSlotDescriptor {
        item: item(
            ProviderSettingId::CopilotBudgetCookieHeader,
            "Manual GitHub Cookie header",
            "Paste a github.com Cookie header. Treat this value like a password.",
            ProviderSettingsSection::Credentials,
            COPILOT_BUDGET_COOKIE_VISIBLE,
            ALWAYS,
            IMPLEMENTED,
            None,
        ),
        slot: ProviderSecretSlot::CopilotBudgetCookie,
        placeholder: Some("Cookie: ..."),
        actions: COPILOT_REFRESH_BUDGET_ACTION,
    }),
    ProviderSettingsControlDescriptor::PlainOption(ProviderSettingsPlainOptionDescriptor {
        item: item(
            ProviderSettingId::CopilotEnterpriseHost,
            "Enterprise host",
            concat!(
                "Optional. Enter your GitHub Enterprise host, for example octocorp.ghe.com. ",
                "Leave blank for github.com."
            ),
            ProviderSettingsSection::Credentials,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            None,
        ),
        placeholder: Some("github.com"),
        actions: NO_ACTIONS,
    }),
];

const COPILOT_ACTIONS: &[ProviderSettingsActionDescriptor] = &[
    ProviderSettingsActionDescriptor {
        id: ProviderSettingsActionId::RefreshCopilotBudgets,
        title: "Refresh budgets",
        style: ProviderSettingsActionStyle::Bordered,
        section: ProviderSettingsSection::Credentials,
        standalone: false,
        target: ProviderSettingsActionTarget::RefreshProvider,
        visible_when: ALWAYS,
        availability: IMPLEMENTED,
    },
    ProviderSettingsActionDescriptor {
        id: ProviderSettingsActionId::AddCopilotAccount,
        title: "GitHub Login",
        style: ProviderSettingsActionStyle::Bordered,
        section: ProviderSettingsSection::Connection,
        standalone: true,
        target: ProviderSettingsActionTarget::Login,
        visible_when: ALWAYS,
        availability: IMPLEMENTED,
    },
];

const COPILOT_ACCOUNT_CREDENTIALS: &[ProviderAccountCredentialKind] =
    &[ProviderAccountCredentialKind::Oauth];
const COPILOT_ACCOUNTS: ProviderAccountSupportDescriptor = ProviderAccountSupportDescriptor {
    title: "GitHub accounts",
    subtitle: "Sign in with multiple GitHub accounts via OAuth.",
    placeholder: "Paste GitHub token…",
    credential_kinds: COPILOT_ACCOUNT_CREDENTIALS,
    organization_field: ProviderAccountFieldMode::Hidden,
    workspace_field: ProviderAccountFieldMode::Hidden,
    requires_manual_cookie_source: false,
    primary_action: Some(ProviderSettingsActionId::AddCopilotAccount),
    token_file_action: None,
    visible_when: ALWAYS,
    availability: unavailable(ProviderSettingsGap::MultiAccountLifecycle),
};

const COPILOT_SETTINGS: ProviderSettingsDescriptor = ProviderSettingsDescriptor {
    schema_version: 1,
    provider: ProviderId::Copilot,
    controls: COPILOT_CONTROLS,
    actions: COPILOT_ACTIONS,
    accounts: Some(COPILOT_ACCOUNTS),
};

const ZAI_REGION_OPTIONS: &[ProviderSettingsPickerOption] = &[
    option(
        ProviderSettingChoice::Global,
        "Global (api.z.ai)",
        IMPLEMENTED,
    ),
    option(
        ProviderSettingChoice::BigModelCn,
        "BigModel CN (open.bigmodel.cn)",
        IMPLEMENTED,
    ),
];
const ZAI_OPEN_KEYS_ACTION: &[ProviderSettingsActionId] =
    &[ProviderSettingsActionId::OpenZaiApiKeys];

const ZAI_CONTROLS: &[ProviderSettingsControlDescriptor] = &[
    ProviderSettingsControlDescriptor::Picker(ProviderSettingsPickerDescriptor {
        item: item(
            ProviderSettingId::ZaiApiRegion,
            "API region",
            concat!(
                "Global uses api.z.ai. China mainland uses open.bigmodel.cn with a BigModel/GLM ",
                "key; the two key families are not interchangeable."
            ),
            ProviderSettingsSection::Connection,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            None,
        ),
        options: ZAI_REGION_OPTIONS,
        dynamic_options: None,
        actions: NO_ACTIONS,
    }),
    ProviderSettingsControlDescriptor::SecretSlot(ProviderSettingsSecretSlotDescriptor {
        item: item(
            ProviderSettingId::ZaiApiKey,
            "API key",
            concat!(
                "Use a key issued for the selected region. China also supports the standard ",
                "BigModel and GLM credential discovery paths."
            ),
            ProviderSettingsSection::Credentials,
            ALWAYS,
            ALWAYS,
            IMPLEMENTED,
            None,
        ),
        slot: ProviderSecretSlot::ZaiApiKey,
        placeholder: Some("Paste z.ai / GLM API key…"),
        actions: ZAI_OPEN_KEYS_ACTION,
    }),
];

const ZAI_ACTIONS: &[ProviderSettingsActionDescriptor] = &[ProviderSettingsActionDescriptor {
    id: ProviderSettingsActionId::OpenZaiApiKeys,
    title: "Open regional API keys",
    style: ProviderSettingsActionStyle::Link,
    section: ProviderSettingsSection::Credentials,
    standalone: false,
    target: ProviderSettingsActionTarget::OpenRegionalCredentialPage,
    visible_when: ALWAYS,
    availability: IMPLEMENTED,
}];

const ZAI_ACCOUNT_CREDENTIALS: &[ProviderAccountCredentialKind] =
    &[ProviderAccountCredentialKind::ApiKey];
const ZAI_ACCOUNTS: ProviderAccountSupportDescriptor = ProviderAccountSupportDescriptor {
    title: "API tokens",
    subtitle: "Store regional z.ai or BigModel API tokens.",
    placeholder: "Paste token…",
    credential_kinds: ZAI_ACCOUNT_CREDENTIALS,
    organization_field: ProviderAccountFieldMode::RequiredInTeamMode,
    workspace_field: ProviderAccountFieldMode::RequiredInTeamMode,
    requires_manual_cookie_source: false,
    primary_action: None,
    token_file_action: None,
    visible_when: ALWAYS,
    availability: unavailable(ProviderSettingsGap::MultiAccountLifecycle),
};

const ZAI_SETTINGS: ProviderSettingsDescriptor = ProviderSettingsDescriptor {
    schema_version: 1,
    provider: ProviderId::Zai,
    controls: ZAI_CONTROLS,
    actions: ZAI_ACTIONS,
    accounts: Some(ZAI_ACCOUNTS),
};

/// Returns static value-free settings metadata for the current flagship set.
///
/// Providers not yet migrated to the typed schema return `None` rather than an
/// empty descriptor, so callers cannot mistake missing metadata for a provider
/// with no settings.
#[must_use]
pub const fn settings_for(provider: ProviderId) -> Option<&'static ProviderSettingsDescriptor> {
    match provider {
        ProviderId::Codex => Some(&CODEX_SETTINGS),
        ProviderId::Claude => Some(&CLAUDE_SETTINGS),
        ProviderId::Grok => Some(&GROK_SETTINGS),
        ProviderId::Copilot => Some(&COPILOT_SETTINGS),
        ProviderId::Zai => Some(&ZAI_SETTINGS),
        _ => None,
    }
}
