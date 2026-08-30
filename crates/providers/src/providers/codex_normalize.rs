//! Pure Codex HTTP response projection into the account-scoped domain model.

use std::collections::BTreeSet;

use oab_domain::{
    AccountScope, BoundedText, CreditLimitSnapshot, CreditsSnapshot, DataConfidence,
    DisplayPercent, ExactDecimal, NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;

use super::codex::CodexBearerCredentials;
use super::codex_http::{
    CodexAdditionalRateLimit, CodexCreditDetails, CodexHttpError, CodexPatUsageFetch,
    CodexRateLimitDetails, CodexSpendControlLimit, CodexUsageResponse, CodexWindowSnapshot,
};
use crate::normalize::UsageSampleBuilder;

const MAX_EXTRA_WINDOWS: usize = 16;
const SESSION_SECONDS: u64 = 5 * 60 * 60;
const WEEKLY_SECONDS: u64 = 7 * 24 * 60 * 60;
const SPARK_FIVE_HOUR_MAX_SECONDS: i64 = 6 * 60 * 60;
const SPARK_WEEKLY_MIN_SECONDS: i64 = 6 * 24 * 60 * 60;

/// Projects a PAT whoami/usage pair into one exact account-scoped sample.
///
/// # Errors
///
/// Returns [`CodexHttpError::InvalidResponse`] when the response has neither
/// core quota windows nor usable credit state, or cannot satisfy domain bounds.
pub fn normalize_codex_pat_usage(
    fetch: &CodexPatUsageFetch,
    scope: AccountScope,
    fetched_at: Timestamp,
) -> Result<UsageSample, CodexHttpError> {
    let whoami = fetch.whoami();
    let plan = response_plan(fetch.usage())
        .or_else(|| whoami.and_then(|identity| clean_optional(identity.plan_type())));
    normalize_http_usage(
        fetch.usage(),
        IdentityFields {
            provider_account_id: whoami.and_then(|identity| clean_optional(identity.account_id())),
            email: whoami.and_then(|identity| clean_optional(identity.email())),
            plan,
        },
        scope,
        fetched_at,
        "pat",
    )
}

/// Projects an OAuth/API-key usage response into one exact account-scoped sample.
///
/// A non-empty managed account override is retained as the displayed provider
/// account ID because it is also the account used by the HTTP request. Otherwise
/// the response account precedes the credential account. Email and fallback plan
/// hints come only from the bounded local ID token.
///
/// # Errors
///
/// Returns [`CodexHttpError::InvalidResponse`] when the response has neither
/// core quota windows nor usable credit state, or cannot satisfy domain bounds.
pub fn normalize_codex_oauth_usage(
    response: &CodexUsageResponse,
    credentials: &CodexBearerCredentials,
    managed_account_override: Option<&str>,
    scope: AccountScope,
    fetched_at: Timestamp,
) -> Result<UsageSample, CodexHttpError> {
    let hints = credentials.identity_hints();
    let provider_account_id = clean_optional(managed_account_override)
        .or_else(|| clean_optional(response.account_id()))
        .or_else(|| clean_optional(credentials.account_id()));
    normalize_http_usage(
        response,
        IdentityFields {
            provider_account_id,
            email: hints.email().map(str::to_owned),
            plan: response_plan(response).or_else(|| hints.plan().map(str::to_owned)),
        },
        scope,
        fetched_at,
        "oauth",
    )
}

struct IdentityFields {
    provider_account_id: Option<String>,
    email: Option<String>,
    plan: Option<String>,
}

fn normalize_http_usage(
    response: &CodexUsageResponse,
    identity: IdentityFields,
    scope: AccountScope,
    fetched_at: Timestamp,
    strategy: &'static str,
) -> Result<UsageSample, CodexHttpError> {
    if scope.provider() != ProviderId::Codex {
        return Err(CodexHttpError::Configuration);
    }
    let mut lossy = response
        .rate_limit()
        .is_some_and(CodexRateLimitDetails::has_window_decode_failure)
        || response.additional_rate_limits_decode_failed()
        || response.identity_metadata_truncated();

    let primary = response
        .rate_limit()
        .and_then(CodexRateLimitDetails::primary_window)
        .map(|snapshot| normalize_window(snapshot, ResetPolicy::AnyRepresentable))
        .transpose()?;
    let secondary = response
        .rate_limit()
        .and_then(CodexRateLimitDetails::secondary_window)
        .map(|snapshot| normalize_window(snapshot, ResetPolicy::AnyRepresentable))
        .transpose()?;
    let primary = primary.map(|(window, window_lossy)| {
        lossy |= window_lossy;
        window
    });
    let secondary = secondary.map(|(window, window_lossy)| {
        lossy |= window_lossy;
        window
    });
    let (primary, secondary) = normalize_window_roles(primary, secondary);
    let has_core_windows = primary.is_some() || secondary.is_some();

    let (credits, credits_lossy) = normalize_credits(response, &scope, fetched_at);
    lossy |= credits_lossy;
    if !has_core_windows && credits.is_none() {
        return Err(CodexHttpError::InvalidResponse);
    }
    // The pinned credits-only branch never promotes confidence to exact.
    lossy |= !has_core_windows;

    let (extra_windows, extra_lossy) = if has_core_windows {
        normalize_extra_windows(response.additional_rate_limits())?
    } else {
        (Vec::new(), false)
    };
    lossy |= extra_lossy;

    let (provider_account_id, account_lossy) =
        normalize_identity_text(identity.provider_account_id);
    let (email, email_lossy) = normalize_identity_text(identity.email);
    let (plan, plan_lossy) = normalize_identity_text(identity.plan);
    lossy |= account_lossy || email_lossy || plan_lossy;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .extra_windows(extra_windows)
        .confidence(if lossy {
            DataConfidence::Unknown
        } else {
            DataConfidence::Exact
        });
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(credits) = credits {
        builder = builder.credits(credits);
    }
    builder
        .provider_account_id(provider_account_id)
        .and_then(|builder| builder.email(email))
        .and_then(|builder| builder.login_method(plan))
        .and_then(|builder| builder.provenance("codex", strategy))
        .and_then(UsageSampleBuilder::build)
        .map_err(|_| CodexHttpError::InvalidResponse)
}

fn response_plan(response: &CodexUsageResponse) -> Option<String> {
    response
        .plan_type()
        .and_then(|plan| clean_optional(Some(plan.raw_value())))
}

fn clean_optional(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn normalize_identity_text(value: Option<String>) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    match BoundedText::<256>::new(&value) {
        Ok(value) => (Some(value.into_string()), false),
        Err(_) => (None, true),
    }
}

fn normalize_window(
    snapshot: &CodexWindowSnapshot,
    reset_policy: ResetPolicy,
) -> Result<(RateWindow, bool), CodexHttpError> {
    let duration_minutes = snapshot
        .limit_window_seconds()
        .checked_div(60)
        .unwrap_or_default();
    let duration = (duration_minutes > 0)
        .then(|| WindowDuration::from_provider_minutes(duration_minutes).ok())
        .flatten();
    let duration_lossy = match reset_policy {
        ResetPolicy::AnyRepresentable => duration_minutes <= 0,
        ResetPolicy::PositiveOnly => snapshot.limit_window_seconds() > 0 && duration_minutes <= 0,
    };
    let resets_at = match reset_policy {
        ResetPolicy::AnyRepresentable => Timestamp::from_unix_timestamp(snapshot.reset_at()).ok(),
        ResetPolicy::PositiveOnly => valid_positive_timestamp(snapshot.reset_at()),
    };
    let reset_lossy = match reset_policy {
        ResetPolicy::AnyRepresentable => resets_at.is_none(),
        ResetPolicy::PositiveOnly => snapshot.reset_at() > 0 && resets_at.is_none(),
    };
    let window = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(
                snapshot
                    .used_percent()
                    .to_f64()
                    .ok_or(CodexHttpError::InvalidResponse)?,
            )
            .map_err(|_| CodexHttpError::InvalidResponse)?,
        ),
        duration,
        resets_at,
        None,
        None,
        false,
    )
    .map_err(|_| CodexHttpError::InvalidResponse)?;
    Ok((window, reset_lossy || duration_lossy))
}

#[derive(Clone, Copy)]
enum ResetPolicy {
    AnyRepresentable,
    PositiveOnly,
}

fn valid_positive_timestamp(seconds: i64) -> Option<Timestamp> {
    (seconds > 0)
        .then(|| Timestamp::from_unix_timestamp(seconds).ok())
        .flatten()
}

fn normalize_window_roles(
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
) -> (Option<RateWindow>, Option<RateWindow>) {
    match (primary, secondary) {
        (Some(primary), Some(secondary))
            if window_role(&primary) == WindowRole::Weekly
                && window_role(&secondary) != WindowRole::Weekly =>
        {
            (Some(secondary), Some(primary))
        }
        (Some(primary), Some(secondary)) => (Some(primary), Some(secondary)),
        (Some(window), None) if window_role(&window) == WindowRole::Weekly => (None, Some(window)),
        (Some(window), None) => (Some(window), None),
        (None, Some(window)) if window_role(&window) != WindowRole::Weekly => (Some(window), None),
        (None, Some(window)) => (None, Some(window)),
        (None, None) => (None, None),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowRole {
    Session,
    Weekly,
    Unknown,
}

fn window_role(window: &RateWindow) -> WindowRole {
    match window
        .duration()
        .map(WindowDuration::seconds)
        .map(|seconds| seconds / 60)
    {
        Some(minutes) if minutes == SESSION_SECONDS / 60 => WindowRole::Session,
        Some(minutes) if minutes == WEEKLY_SECONDS / 60 => WindowRole::Weekly,
        _ => WindowRole::Unknown,
    }
}

fn normalize_credits(
    response: &CodexUsageResponse,
    scope: &AccountScope,
    fetched_at: Timestamp,
) -> (Option<CreditsSnapshot>, bool) {
    let balance_value = response.credits().and_then(CodexCreditDetails::balance);
    let balance = balance_value
        .and_then(Decimal::from_f64_retain)
        .map(|value| value.max(Decimal::ZERO));
    let mut lossy = (balance_value.is_some() && balance.is_none())
        || balance_value.is_some_and(|value| value < 0.0);
    let (limit, limit_lossy) =
        normalize_credit_limit(response.resolved_individual_limit(), fetched_at);
    lossy |= limit_lossy;
    if balance.is_none() && limit.is_none() {
        return (None, lossy);
    }
    match CreditsSnapshot::new(
        scope.clone(),
        ExactDecimal::new(balance.unwrap_or(Decimal::ZERO)),
        Vec::new(),
        fetched_at,
        limit,
    ) {
        Ok(credits) => (Some(credits), lossy),
        Err(_) => (None, true),
    }
}

fn normalize_credit_limit(
    snapshot: Option<&CodexSpendControlLimit>,
    fetched_at: Timestamp,
) -> (Option<CreditLimitSnapshot>, bool) {
    let Some(snapshot) = snapshot else {
        return (None, false);
    };
    let Some(raw_limit) = snapshot.limit().filter(|limit| *limit > 0.0) else {
        return (None, false);
    };
    let Some(limit) = Decimal::from_f64_retain(raw_limit) else {
        return (None, true);
    };
    let supplied_remaining = match snapshot.remaining_percent() {
        Some(value) => match Decimal::from_f64_retain(value) {
            Some(value) => Some(value.clamp(Decimal::ZERO, Decimal::ONE_HUNDRED)),
            None => return (None, true),
        },
        None => None,
    };
    let used = match snapshot.used() {
        Some(value) => match Decimal::from_f64_retain(value) {
            Some(value) => value.max(Decimal::ZERO),
            None => return (None, true),
        },
        None => match supplied_remaining {
            Some(remaining) => {
                let Some(used) = Decimal::ONE_HUNDRED
                    .checked_sub(remaining)
                    .and_then(|value| value.checked_mul(limit))
                    .and_then(|value| value.checked_div(Decimal::ONE_HUNDRED))
                else {
                    return (None, true);
                };
                used
            }
            None => Decimal::ZERO,
        },
    };
    let remaining = if let Some(remaining) = supplied_remaining {
        remaining
    } else {
        let Some(remaining) = used
            .checked_mul(Decimal::ONE_HUNDRED)
            .and_then(|value| value.checked_div(limit))
            .and_then(|value| Decimal::ONE_HUNDRED.checked_sub(value))
        else {
            return (None, true);
        };
        remaining.clamp(Decimal::ZERO, Decimal::ONE_HUNDRED)
    };
    let Some(remaining) = remaining.to_f64() else {
        return (None, true);
    };
    let Ok(remaining) = DisplayPercent::new(remaining) else {
        return (None, true);
    };
    let resets_at = snapshot.resets_at().and_then(valid_positive_timestamp);
    let invalid_reset = snapshot
        .resets_at()
        .is_some_and(|seconds| seconds > 0 && resets_at.is_none());
    match CreditLimitSnapshot::new(
        "Monthly credit limit",
        ExactDecimal::new(used),
        ExactDecimal::new(limit),
        remaining,
        resets_at,
        fetched_at,
    ) {
        Ok(limit) => (Some(limit), invalid_reset),
        Err(_) => (None, true),
    }
}

fn normalize_extra_windows(
    entries: Option<&[CodexAdditionalRateLimit]>,
) -> Result<(Vec<NamedRateWindow>, bool), CodexHttpError> {
    let Some(entries) = entries else {
        return Ok((Vec::new(), false));
    };
    let mut windows = Vec::new();
    let mut used_ids = BTreeSet::new();
    let mut lossy = false;
    for entry in entries {
        if is_spark(entry) {
            let rate = entry.rate_limit();
            let candidates = [
                (
                    rate.and_then(CodexRateLimitDetails::primary_window),
                    SparkWindowKind::FiveHour,
                ),
                (
                    rate.and_then(CodexRateLimitDetails::secondary_window),
                    SparkWindowKind::Weekly,
                ),
            ];
            for (snapshot, fallback) in candidates {
                let Some(snapshot) = snapshot else { continue };
                let kind = spark_window_kind(snapshot, fallback);
                push_named_window(
                    &mut windows,
                    &mut used_ids,
                    kind.id(),
                    kind.title(),
                    snapshot,
                    &mut lossy,
                )?;
            }
        } else {
            let Some(snapshot) = entry
                .rate_limit()
                .and_then(|rate| rate.primary_window().or_else(|| rate.secondary_window()))
            else {
                continue;
            };
            let Some(source) = first_nonempty(entry.metered_feature(), entry.limit_name()) else {
                continue;
            };
            let slug = slug(source);
            if slug.is_empty() {
                continue;
            }
            let id = format!("codex-{slug}");
            let title = first_nonempty(entry.limit_name(), entry.metered_feature())
                .unwrap_or("Codex extra limit");
            push_named_window(
                &mut windows,
                &mut used_ids,
                &id,
                title,
                snapshot,
                &mut lossy,
            )?;
        }
    }
    Ok((windows, lossy))
}

fn push_named_window(
    windows: &mut Vec<NamedRateWindow>,
    used_ids: &mut BTreeSet<String>,
    id: &str,
    title: &str,
    snapshot: &CodexWindowSnapshot,
    lossy: &mut bool,
) -> Result<(), CodexHttpError> {
    if used_ids.contains(id) {
        return Ok(());
    }
    if windows.len() >= MAX_EXTRA_WINDOWS {
        *lossy = true;
        return Ok(());
    }
    let Ok(id) = BoundedText::<128>::new(id) else {
        *lossy = true;
        return Ok(());
    };
    let Ok(title) = BoundedText::<120>::new(title) else {
        *lossy = true;
        return Ok(());
    };
    let id_string = id.as_str().to_owned();
    let (window, window_lossy) = normalize_window(snapshot, ResetPolicy::PositiveOnly)?;
    *lossy |= window_lossy;
    windows.push(NamedRateWindow::new(id, title, window));
    used_ids.insert(id_string);
    Ok(())
}

#[derive(Clone, Copy)]
enum SparkWindowKind {
    FiveHour,
    Weekly,
}

impl SparkWindowKind {
    const fn id(self) -> &'static str {
        match self {
            Self::FiveHour => "codex-spark",
            Self::Weekly => "codex-spark-weekly",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::FiveHour => "Codex Spark 5-hour",
            Self::Weekly => "Codex Spark Weekly",
        }
    }
}

fn spark_window_kind(snapshot: &CodexWindowSnapshot, fallback: SparkWindowKind) -> SparkWindowKind {
    let seconds = snapshot.limit_window_seconds();
    let minutes = seconds.checked_div(60).unwrap_or_default();
    if minutes > 0 && minutes <= SPARK_FIVE_HOUR_MAX_SECONDS / 60 {
        SparkWindowKind::FiveHour
    } else if minutes >= SPARK_WEEKLY_MIN_SECONDS / 60 {
        SparkWindowKind::Weekly
    } else {
        fallback
    }
}

fn is_spark(entry: &CodexAdditionalRateLimit) -> bool {
    [entry.limit_name(), entry.metered_feature()]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains("spark"))
}

fn first_nonempty<'a>(first: Option<&'a str>, second: Option<&'a str>) -> Option<&'a str> {
    [first, second]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn slug(value: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;
    for character in value.to_lowercase().chars() {
        if character.is_alphanumeric() {
            output.push(character);
            last_was_dash = false;
        } else if !last_was_dash {
            output.push('-');
            last_was_dash = true;
        }
    }
    output.trim_matches('-').to_owned()
}
