use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp, UsageSample,
};
use oab_providers::normalize::UsageSampleBuilder;
use oab_providers::providers::codex::{
    CodexCredentialError, CodexPatHomeScope, CodexSourceAttempt, CodexSourceMode,
};
use oab_providers::providers::codex_app_server::CodexAppServerError;
use oab_providers::providers::codex_http::CodexHttpError;
use oab_providers::providers::codex_provider::{
    CodexAccountSelection, CodexAttemptFuture, CodexAttemptOutcome, CodexAttemptRunner,
    CodexCoordinator, CodexCoordinatorError, CodexCoordinatorSettings, CodexManagedWorkspaceId,
};
use tokio_util::sync::CancellationToken;

fn scope(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new("codex-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn fetched_at() -> Timestamp {
    Timestamp::parse("2026-08-30T12:00:00Z").expect("test timestamp")
}

fn sample(scope: AccountScope, strategy: &'static str) -> UsageSample {
    UsageSampleBuilder::new(scope, fetched_at())
        .provenance("codex", strategy)
        .expect("fixed provenance")
        .build()
        .expect("sample")
}

fn settings(mode: CodexSourceMode, account: CodexAccountSelection) -> CodexCoordinatorSettings {
    CodexCoordinatorSettings::new(mode, account, false, Some("codex-cli 1.2.3".to_owned()))
        .expect("settings")
}

struct ScriptStep {
    expected: CodexSourceAttempt,
    outcome: CodexAttemptOutcome,
    cancel_after: bool,
}

impl ScriptStep {
    fn new(expected: CodexSourceAttempt, outcome: CodexAttemptOutcome) -> Self {
        Self {
            expected,
            outcome,
            cancel_after: false,
        }
    }

    fn cancelling(mut self) -> Self {
        self.cancel_after = true;
        self
    }
}

#[derive(Clone)]
struct ObservedCall {
    attempt: CodexSourceAttempt,
    settings: CodexCoordinatorSettings,
    scope: AccountScope,
    fetched_at: Timestamp,
}

struct ScriptedRunner {
    steps: Mutex<VecDeque<ScriptStep>>,
    calls: Mutex<Vec<ObservedCall>>,
}

impl ScriptedRunner {
    fn new(steps: impl IntoIterator<Item = ScriptStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<ObservedCall> {
        self.calls.lock().expect("call lock").clone()
    }
}

impl CodexAttemptRunner for ScriptedRunner {
    fn run<'a>(
        &'a self,
        attempt: CodexSourceAttempt,
        settings: &'a CodexCoordinatorSettings,
        scope: &'a AccountScope,
        fetched_at: Timestamp,
        cancellation: &'a CancellationToken,
    ) -> CodexAttemptFuture<'a> {
        let step = self
            .steps
            .lock()
            .expect("step lock")
            .pop_front()
            .expect("unexpected coordinator attempt");
        assert_eq!(attempt, step.expected, "attempt order");
        self.calls.lock().expect("call lock").push(ObservedCall {
            attempt,
            settings: settings.clone(),
            scope: scope.clone(),
            fetched_at,
        });
        let cancellation = cancellation.clone();
        Box::pin(async move {
            if step.cancel_after {
                cancellation.cancel();
            }
            step.outcome
        })
    }
}

fn attempts(runner: &ScriptedRunner) -> Vec<CodexSourceAttempt> {
    runner.calls().iter().map(|call| call.attempt).collect()
}

#[test]
fn managed_workspace_ids_are_trimmed_bounded_and_redacted() {
    let id = CodexManagedWorkspaceId::new("  workspace-secret  ").expect("workspace ID");
    assert_eq!(id.as_str(), "workspace-secret");
    assert!(!format!("{id:?}").contains("workspace-secret"));

    for invalid in [
        "",
        "   ",
        "workspace\rsecret",
        "workspace\nsecret",
        "workspace\tsecret",
        "workspace\0secret",
    ] {
        assert_eq!(
            CodexManagedWorkspaceId::new(invalid).expect_err("invalid workspace ID"),
            CodexCoordinatorError::Configuration
        );
    }
    assert!(CodexManagedWorkspaceId::new("x".repeat(1024)).is_ok());
    assert_eq!(
        CodexManagedWorkspaceId::new("x".repeat(1025)).expect_err("oversized workspace ID"),
        CodexCoordinatorError::Configuration
    );
}

#[test]
fn account_selection_exposes_only_the_explicit_managed_header() {
    let managed_id = CodexManagedWorkspaceId::new("managed-secret").expect("managed ID");
    let cases = [
        (
            CodexAccountSelection::Ambient,
            CodexPatHomeScope::Ambient,
            None,
            false,
            true,
        ),
        (
            CodexAccountSelection::Profile,
            CodexPatHomeScope::Profile,
            None,
            false,
            true,
        ),
        (
            CodexAccountSelection::Managed(managed_id),
            CodexPatHomeScope::Managed,
            Some("managed-secret"),
            true,
            false,
        ),
        (
            CodexAccountSelection::FailClosedManaged,
            CodexPatHomeScope::FailClosed,
            None,
            true,
            false,
        ),
    ];

    for (selection, pat_scope, managed_id, managed, allows_cli) in cases {
        assert_eq!(selection.pat_scope(), pat_scope);
        assert_eq!(selection.managed_account_id(), managed_id);
        assert_eq!(selection.managed_selected(), managed);
        assert_eq!(selection.allows_cli(), allows_cli);
        assert!(!format!("{selection:?}").contains("managed-secret"));
    }
}

#[test]
fn settings_normalize_and_redact_resolved_cli_version() {
    let settings = CodexCoordinatorSettings::new(
        CodexSourceMode::OAuth,
        CodexAccountSelection::Ambient,
        true,
        Some("  codex-cli secret-build  ".to_owned()),
    )
    .expect("settings");
    assert_eq!(settings.mode(), CodexSourceMode::OAuth);
    assert!(settings.allow_external_oauth());
    assert_eq!(
        settings.resolved_cli_version(),
        Some("codex-cli secret-build")
    );
    let debug = format!("{settings:?}");
    assert!(debug.contains("has_cli_version: true"));
    assert!(!debug.contains("secret-build"));

    let blank = CodexCoordinatorSettings::new(
        CodexSourceMode::Auto,
        CodexAccountSelection::Ambient,
        false,
        Some(" \t ".to_owned()),
    )
    .expect("blank version");
    assert_eq!(blank.resolved_cli_version(), None);

    for invalid in ["codex\n1", "codex\t1"] {
        assert_eq!(
            CodexCoordinatorSettings::new(
                CodexSourceMode::Auto,
                CodexAccountSelection::Ambient,
                false,
                Some(invalid.to_owned())
            )
            .expect_err("invalid version"),
            CodexCoordinatorError::Configuration
        );
    }
    assert_eq!(
        CodexCoordinatorSettings::new(
            CodexSourceMode::Auto,
            CodexAccountSelection::Ambient,
            false,
            Some("x".repeat(129))
        )
        .expect_err("oversized version"),
        CodexCoordinatorError::Configuration
    );
}

#[tokio::test]
async fn automatic_ambient_plan_runs_pat_oauth_then_cli() {
    let exact_scope = scope(ProviderId::Codex, "local-account");
    let expected = sample(exact_scope.clone(), "cli");
    let runner = Arc::new(ScriptedRunner::new([
        ScriptStep::new(CodexSourceAttempt::Pat, CodexAttemptOutcome::Unavailable),
        ScriptStep::new(CodexSourceAttempt::OAuth, CodexAttemptOutcome::Unavailable),
        ScriptStep::new(
            CodexSourceAttempt::Cli,
            CodexAttemptOutcome::Success(expected.clone()),
        ),
    ]));
    let coordinator = CodexCoordinator::new(
        exact_scope.clone(),
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner.clone(),
    );

    let actual = coordinator
        .fetch_at(fetched_at(), &CancellationToken::new())
        .await
        .expect("CLI winner");
    assert_eq!(actual, expected, "winning sample must be unchanged");
    assert_eq!(
        attempts(&runner),
        [
            CodexSourceAttempt::Pat,
            CodexSourceAttempt::OAuth,
            CodexSourceAttempt::Cli
        ]
    );
    for call in runner.calls() {
        assert_eq!(call.scope, exact_scope);
        assert_eq!(call.fetched_at, fetched_at());
        assert_eq!(call.settings.mode(), CodexSourceMode::Auto);
        assert_eq!(
            call.settings.resolved_cli_version(),
            Some("codex-cli 1.2.3")
        );
    }
}

#[tokio::test]
async fn automatic_managed_plans_omit_ambient_cli() {
    let selections = [
        CodexAccountSelection::Managed(
            CodexManagedWorkspaceId::new("provider-workspace").expect("managed ID"),
        ),
        CodexAccountSelection::FailClosedManaged,
    ];
    for selection in selections {
        let runner = Arc::new(ScriptedRunner::new([
            ScriptStep::new(CodexSourceAttempt::Pat, CodexAttemptOutcome::Unavailable),
            ScriptStep::new(CodexSourceAttempt::OAuth, CodexAttemptOutcome::Unavailable),
        ]));
        let coordinator = CodexCoordinator::new(
            scope(ProviderId::Codex, "local-route-not-provider-id"),
            settings(CodexSourceMode::Auto, selection),
            runner.clone(),
        );

        assert_eq!(
            coordinator
                .fetch_at(fetched_at(), &CancellationToken::new())
                .await
                .expect_err("all managed sources unavailable"),
            CodexCoordinatorError::MissingCredential
        );
        assert_eq!(
            attempts(&runner),
            [CodexSourceAttempt::Pat, CodexSourceAttempt::OAuth]
        );
    }
}

#[tokio::test]
async fn explicit_modes_execute_only_their_closed_plans() {
    let pat_scope = scope(ProviderId::Codex, "pat-account");
    let pat_sample = sample(pat_scope.clone(), "pat");
    let pat_runner = Arc::new(ScriptedRunner::new([ScriptStep::new(
        CodexSourceAttempt::Pat,
        CodexAttemptOutcome::Success(pat_sample.clone()),
    )]));
    let pat = CodexCoordinator::new(
        pat_scope,
        settings(CodexSourceMode::Pat, CodexAccountSelection::Ambient),
        pat_runner.clone(),
    );
    assert_eq!(
        pat.fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect("PAT"),
        pat_sample
    );
    assert_eq!(attempts(&pat_runner), [CodexSourceAttempt::Pat]);

    let oauth_scope = scope(ProviderId::Codex, "oauth-account");
    let recovered = sample(oauth_scope.clone(), "cli-owner-recovery");
    let oauth_runner = Arc::new(ScriptedRunner::new([
        ScriptStep::new(
            CodexSourceAttempt::OAuth,
            CodexAttemptOutcome::Failed(CodexCoordinatorError::Credential(
                CodexCredentialError::NativeRefreshRequired,
            )),
        ),
        ScriptStep::new(
            CodexSourceAttempt::CliOwnerRecovery,
            CodexAttemptOutcome::Success(recovered.clone()),
        ),
    ]));
    let oauth = CodexCoordinator::new(
        oauth_scope,
        settings(CodexSourceMode::OAuth, CodexAccountSelection::Profile),
        oauth_runner.clone(),
    );
    assert_eq!(
        oauth
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect("owner recovery"),
        recovered
    );
    assert_eq!(
        attempts(&oauth_runner),
        [
            CodexSourceAttempt::OAuth,
            CodexSourceAttempt::CliOwnerRecovery
        ]
    );

    let cli_scope = scope(ProviderId::Codex, "cli-account");
    let cli_sample = sample(cli_scope.clone(), "cli");
    let cli_runner = Arc::new(ScriptedRunner::new([ScriptStep::new(
        CodexSourceAttempt::Cli,
        CodexAttemptOutcome::Success(cli_sample.clone()),
    )]));
    let cli = CodexCoordinator::new(
        cli_scope,
        settings(CodexSourceMode::Cli, CodexAccountSelection::Ambient),
        cli_runner.clone(),
    );
    assert_eq!(
        cli.fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect("CLI"),
        cli_sample
    );
    assert_eq!(attempts(&cli_runner), [CodexSourceAttempt::Cli]);
}

#[tokio::test]
async fn unavailable_attempts_do_not_replace_the_last_available_failure() {
    let runner = Arc::new(ScriptedRunner::new([
        ScriptStep::new(
            CodexSourceAttempt::Pat,
            CodexAttemptOutcome::Failed(CodexCoordinatorError::Http(CodexHttpError::Unauthorized)),
        ),
        ScriptStep::new(CodexSourceAttempt::OAuth, CodexAttemptOutcome::Unavailable),
        ScriptStep::new(CodexSourceAttempt::Cli, CodexAttemptOutcome::Unavailable),
    ]));
    let coordinator = CodexCoordinator::new(
        scope(ProviderId::Codex, "account"),
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner.clone(),
    );

    assert_eq!(
        coordinator
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect_err("last available failure"),
        CodexCoordinatorError::Http(CodexHttpError::Unauthorized)
    );
    assert_eq!(attempts(&runner).len(), 3);
}

#[tokio::test]
async fn a_non_fallback_failure_stops_without_inspecting_later_sources() {
    let runner = Arc::new(ScriptedRunner::new([ScriptStep::new(
        CodexSourceAttempt::Pat,
        CodexAttemptOutcome::Failed(CodexCoordinatorError::Http(CodexHttpError::Network)),
    )]));
    let coordinator = CodexCoordinator::new(
        scope(ProviderId::Codex, "account"),
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner.clone(),
    );

    assert_eq!(
        coordinator
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect_err("network is terminal for the plan"),
        CodexCoordinatorError::Http(CodexHttpError::Network)
    );
    assert_eq!(attempts(&runner), [CodexSourceAttempt::Pat]);
}

#[tokio::test]
async fn later_available_failure_replaces_an_earlier_fallback_safe_failure() {
    let runner = Arc::new(ScriptedRunner::new([
        ScriptStep::new(
            CodexSourceAttempt::Pat,
            CodexAttemptOutcome::Failed(CodexCoordinatorError::Http(CodexHttpError::Unauthorized)),
        ),
        ScriptStep::new(
            CodexSourceAttempt::OAuth,
            CodexAttemptOutcome::Failed(CodexCoordinatorError::Credential(
                CodexCredentialError::NativeRefreshRequired,
            )),
        ),
        ScriptStep::new(
            CodexSourceAttempt::Cli,
            CodexAttemptOutcome::Failed(CodexCoordinatorError::Cli(CodexAppServerError::Transport)),
        ),
    ]));
    let coordinator = CodexCoordinator::new(
        scope(ProviderId::Codex, "account"),
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner,
    );

    assert_eq!(
        coordinator
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect_err("latest available failure"),
        CodexCoordinatorError::Cli(CodexAppServerError::Transport)
    );
}

#[tokio::test]
async fn cancellation_before_the_plan_never_calls_the_runner() {
    let runner = Arc::new(ScriptedRunner::new([]));
    let coordinator = CodexCoordinator::new(
        scope(ProviderId::Codex, "account"),
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner.clone(),
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    assert_eq!(
        coordinator
            .fetch_at(fetched_at(), &cancellation)
            .await
            .expect_err("cancelled"),
        CodexCoordinatorError::Cancelled
    );
    assert!(runner.calls().is_empty());
}

#[tokio::test]
async fn cancellation_after_an_attempt_wins_over_its_success() {
    let exact_scope = scope(ProviderId::Codex, "account");
    let runner = Arc::new(ScriptedRunner::new([ScriptStep::new(
        CodexSourceAttempt::Pat,
        CodexAttemptOutcome::Success(sample(exact_scope.clone(), "pat")),
    )
    .cancelling()]));
    let coordinator = CodexCoordinator::new(
        exact_scope,
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner.clone(),
    );

    assert_eq!(
        coordinator
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect_err("post-attempt cancellation"),
        CodexCoordinatorError::Cancelled
    );
    assert_eq!(attempts(&runner), [CodexSourceAttempt::Pat]);
}

#[tokio::test]
async fn classified_cancellation_failures_never_fall_back() {
    let errors = [
        CodexCoordinatorError::Cancelled,
        CodexCoordinatorError::Http(CodexHttpError::Cancelled),
        CodexCoordinatorError::Cli(CodexAppServerError::Cancelled),
    ];
    for error in errors {
        let runner = Arc::new(ScriptedRunner::new([ScriptStep::new(
            CodexSourceAttempt::Pat,
            CodexAttemptOutcome::Failed(error),
        )]));
        let coordinator = CodexCoordinator::new(
            scope(ProviderId::Codex, "account"),
            settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
            runner.clone(),
        );

        assert_eq!(
            coordinator
                .fetch_at(fetched_at(), &CancellationToken::new())
                .await
                .expect_err("cancellation failure"),
            error
        );
        assert_eq!(attempts(&runner), [CodexSourceAttempt::Pat]);
    }
}

#[tokio::test]
async fn coordinator_rejects_foreign_provider_and_foreign_sample_scopes() {
    let wrong_provider_runner = Arc::new(ScriptedRunner::new([]));
    let wrong_provider = CodexCoordinator::new(
        scope(ProviderId::Claude, "account"),
        settings(CodexSourceMode::Pat, CodexAccountSelection::Ambient),
        wrong_provider_runner.clone(),
    );
    assert_eq!(
        wrong_provider
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect_err("wrong provider"),
        CodexCoordinatorError::Configuration
    );
    assert!(wrong_provider_runner.calls().is_empty());

    let exact_scope = scope(ProviderId::Codex, "account-one");
    let runner = Arc::new(ScriptedRunner::new([ScriptStep::new(
        CodexSourceAttempt::Pat,
        CodexAttemptOutcome::Success(sample(scope(ProviderId::Codex, "account-two"), "foreign")),
    )]));
    let coordinator = CodexCoordinator::new(
        exact_scope,
        settings(CodexSourceMode::Auto, CodexAccountSelection::Ambient),
        runner.clone(),
    );
    assert_eq!(
        coordinator
            .fetch_at(fetched_at(), &CancellationToken::new())
            .await
            .expect_err("foreign sample scope"),
        CodexCoordinatorError::Configuration
    );
    assert_eq!(attempts(&runner), [CodexSourceAttempt::Pat]);
}

#[test]
fn coordinator_errors_have_stable_public_classifications() {
    let cases = [
        (CodexCoordinatorError::Cancelled, ErrorKind::Network),
        (
            CodexCoordinatorError::MissingCredential,
            ErrorKind::MissingCredential,
        ),
        (CodexCoordinatorError::Configuration, ErrorKind::Api),
        (
            CodexCoordinatorError::Credential(CodexCredentialError::Invalid),
            ErrorKind::Parse,
        ),
        (
            CodexCoordinatorError::Credential(CodexCredentialError::ReadOnlySource),
            ErrorKind::AuthenticationExpired,
        ),
        (
            CodexCoordinatorError::Http(CodexHttpError::Unauthorized),
            ErrorKind::AuthenticationExpired,
        ),
        (
            CodexCoordinatorError::Cli(CodexAppServerError::Transport),
            ErrorKind::Network,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.classified().kind(), expected);
    }
}

#[test]
fn coordinator_debug_never_exposes_managed_or_version_ids() {
    let managed = "managed-provider-secret";
    let version = "private-build-identifier";
    let settings = CodexCoordinatorSettings::new(
        CodexSourceMode::Auto,
        CodexAccountSelection::Managed(CodexManagedWorkspaceId::new(managed).expect("managed ID")),
        true,
        Some(version.to_owned()),
    )
    .expect("settings");
    let runner = Arc::new(ScriptedRunner::new([]));
    let coordinator = CodexCoordinator::new(
        scope(ProviderId::Codex, "local-account-secret"),
        settings,
        runner,
    );

    let debug = format!("{coordinator:?}");
    assert!(!debug.contains(managed));
    assert!(!debug.contains(version));
    assert!(!debug.contains("local-account-secret"));
}
