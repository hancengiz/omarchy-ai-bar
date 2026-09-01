use std::collections::BTreeSet;

use oab_domain::ProviderId;
use oab_providers::registry::descriptor_for;
use oab_providers::settings_descriptor::{
    ProviderAccountFieldMode, ProviderSettingChoice, ProviderSettingId, ProviderSettingsActionId,
    ProviderSettingsAvailability, ProviderSettingsCondition, ProviderSettingsControlDescriptor,
    ProviderSettingsDescriptor,
};
use serde_json::Value;

const FLAGSHIP: [ProviderId; 5] = [
    ProviderId::Codex,
    ProviderId::Claude,
    ProviderId::Grok,
    ProviderId::Copilot,
    ProviderId::Zai,
];

fn picker(
    descriptor: &ProviderSettingsDescriptor,
    id: ProviderSettingId,
) -> &oab_providers::settings_descriptor::ProviderSettingsPickerDescriptor {
    match descriptor.control(id).expect("picker exists") {
        ProviderSettingsControlDescriptor::Picker(picker) => picker,
        _ => panic!("control must be a picker"),
    }
}

fn assert_condition_references_exist(
    condition: ProviderSettingsCondition,
    controls: &BTreeSet<ProviderSettingId>,
) {
    match condition {
        ProviderSettingsCondition::Always
        | ProviderSettingsCondition::Feature { .. }
        | ProviderSettingsCondition::RuntimeFact { .. } => {}
        ProviderSettingsCondition::All { conditions }
        | ProviderSettingsCondition::Any { conditions } => {
            for condition in conditions {
                assert_condition_references_exist(*condition, controls);
            }
        }
        ProviderSettingsCondition::Choice { setting, .. }
        | ProviderSettingsCondition::Toggle { setting, .. } => {
            assert!(
                controls.contains(&setting),
                "missing dependency {setting:?}"
            );
        }
    }
}

fn assert_public_keys(value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                assert!(
                    ![
                        "value",
                        "current_value",
                        "default_value",
                        "secret",
                        "token",
                        "cookie_header",
                        "environment_key",
                        "command",
                        "url",
                    ]
                    .contains(&key.as_str()),
                    "unsafe descriptor field {key}"
                );
                assert_public_keys(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_public_keys(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn flagship_descriptors_are_complete_static_and_other_providers_are_explicitly_unmigrated() {
    let expected_counts = [
        (ProviderId::Codex, 9, 1),
        (ProviderId::Claude, 11, 0),
        (ProviderId::Grok, 3, 2),
        (ProviderId::Copilot, 5, 2),
        (ProviderId::Zai, 2, 1),
    ];
    for (provider, controls, actions) in expected_counts {
        let settings = descriptor_for(provider)
            .settings()
            .expect("migrated settings");
        assert_eq!(settings.provider, provider);
        assert_eq!(settings.schema_version, 1);
        assert_eq!(settings.controls.len(), controls);
        assert_eq!(settings.actions.len(), actions);
        assert!(settings.accounts.is_some());
    }

    for provider in ProviderId::ALL {
        assert_eq!(
            descriptor_for(provider).settings().is_some(),
            FLAGSHIP.contains(&provider),
            "migration-set drift for {provider}"
        );
    }
}

#[test]
fn source_picker_options_never_claim_unimplemented_paths_are_actionable() {
    let codex = descriptor_for(ProviderId::Codex)
        .settings()
        .expect("Codex settings");
    assert!(
        picker(codex, ProviderSettingId::CodexUsageSource)
            .options
            .iter()
            .all(|option| option.availability.is_implemented())
    );

    let claude = descriptor_for(ProviderId::Claude)
        .settings()
        .expect("Claude settings");
    let claude_source = picker(claude, ProviderSettingId::ClaudeUsageSource);
    for option in claude_source.options {
        let expected = matches!(
            option.choice,
            ProviderSettingChoice::Auto | ProviderSettingChoice::Oauth | ProviderSettingChoice::Cli
        );
        assert_eq!(option.availability.is_implemented(), expected);
    }

    let grok = descriptor_for(ProviderId::Grok)
        .settings()
        .expect("Grok settings");
    let grok_source = picker(grok, ProviderSettingId::GrokUsageSource);
    assert!(
        grok_source
            .options
            .iter()
            .all(|option| option.availability.is_implemented())
    );
    for setting in [
        ProviderSettingId::GrokUsageSource,
        ProviderSettingId::GrokCookieSource,
        ProviderSettingId::GrokCookieHeader,
    ] {
        assert!(
            grok.control(setting)
                .is_some_and(|control| control.is_implemented()),
            "Grok source path is not actionable for {setting:?}"
        );
    }

    let copilot = descriptor_for(ProviderId::Copilot)
        .settings()
        .expect("Copilot settings");
    let cookie_source = picker(copilot, ProviderSettingId::CopilotBudgetCookieSource);
    for option in cookie_source.options {
        assert_eq!(
            option.availability.is_implemented(),
            option.choice == ProviderSettingChoice::Manual
        );
    }
    for setting in [
        ProviderSettingId::CopilotBudgetExtras,
        ProviderSettingId::CopilotBudgetCookieSource,
        ProviderSettingId::CopilotBudgetCookieHeader,
    ] {
        assert!(
            copilot
                .control(setting)
                .is_some_and(|control| control.is_implemented()),
            "manual Copilot budget path is not actionable for {setting:?}"
        );
    }
}

#[test]
fn dependencies_and_action_references_are_closed_within_each_provider() {
    for provider in FLAGSHIP {
        let descriptor = descriptor_for(provider)
            .settings()
            .expect("flagship settings");
        let control_ids = descriptor
            .controls
            .iter()
            .map(|control| control.item().id)
            .collect::<BTreeSet<_>>();
        assert_eq!(control_ids.len(), descriptor.controls.len());
        let action_ids = descriptor
            .actions
            .iter()
            .map(|action| action.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(action_ids.len(), descriptor.actions.len());

        for control in descriptor.controls {
            let item = control.item();
            assert_condition_references_exist(item.visible_when, &control_ids);
            assert_condition_references_exist(item.enabled_when, &control_ids);
            let actions = match control {
                ProviderSettingsControlDescriptor::Picker(control) => control.actions,
                ProviderSettingsControlDescriptor::Toggle(control) => control.actions,
                ProviderSettingsControlDescriptor::PlainOption(control) => control.actions,
                ProviderSettingsControlDescriptor::SecretSlot(control) => control.actions,
            };
            for action in actions {
                assert!(action_ids.contains(action));
            }
        }
        for action in descriptor.actions {
            assert_condition_references_exist(action.visible_when, &control_ids);
        }
        if let Some(accounts) = descriptor.accounts {
            assert_condition_references_exist(accounts.visible_when, &control_ids);
            for action in [accounts.primary_action, accounts.token_file_action]
                .into_iter()
                .flatten()
            {
                assert!(action_ids.contains(&action));
            }
        }
    }
}

#[test]
fn serialized_schema_is_value_free_and_contains_no_secret_routing_details() {
    for provider in FLAGSHIP {
        let descriptor = descriptor_for(provider)
            .settings()
            .expect("flagship settings");
        let json = serde_json::to_value(descriptor).expect("serialize descriptor");
        assert_public_keys(&json);
        let encoded = serde_json::to_string(&json).expect("encode descriptor");
        for forbidden in [
            "OMARCHY_AI_BAR_",
            "Z_AI_API_KEY",
            "GROK_OAUTH_TOKEN",
            "COPILOT_API_TOKEN",
            "ANTHROPIC_OAUTH_TOKEN",
            "https://",
            "access_token",
            "refresh_token",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "serialized metadata exposed {forbidden}"
            );
        }
    }
}

#[test]
fn account_metadata_retains_upstream_field_requirements_but_stays_non_actionable() {
    let claude = descriptor_for(ProviderId::Claude)
        .settings()
        .and_then(|descriptor| descriptor.accounts)
        .expect("Claude accounts");
    assert_eq!(
        claude.organization_field,
        ProviderAccountFieldMode::Optional
    );
    assert!(claude.requires_manual_cookie_source);
    assert!(matches!(
        claude.availability,
        ProviderSettingsAvailability::Unavailable { .. }
    ));

    let zai = descriptor_for(ProviderId::Zai)
        .settings()
        .and_then(|descriptor| descriptor.accounts)
        .expect("z.ai accounts");
    assert_eq!(
        zai.organization_field,
        ProviderAccountFieldMode::RequiredInTeamMode
    );
    assert_eq!(
        zai.workspace_field,
        ProviderAccountFieldMode::RequiredInTeamMode
    );

    let copilot = descriptor_for(ProviderId::Copilot)
        .settings()
        .expect("Copilot settings");
    let add_account = copilot
        .action(ProviderSettingsActionId::AddCopilotAccount)
        .expect("add-account action");
    assert!(add_account.standalone);
    assert!(add_account.availability.is_implemented());
    assert!(
        copilot
            .control(ProviderSettingId::CopilotEnterpriseHost)
            .expect("enterprise host")
            .is_implemented()
    );
}
