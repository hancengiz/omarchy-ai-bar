//! `Augment` usage adapter backed by the shell-free `auggie account status` command.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use time::{Date, Month, Time};

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::subprocess::{SubprocessError, SubprocessRequest};

const CLI_OVERRIDE: &str = "OMARCHY_AI_BAR_AUGGIE_CLI_PATH";
const MAX_STDOUT_BYTES: usize = 256 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Resolved Auggie CLI configuration.
pub struct AugmentCliSettings {
    executable: ExecutablePath,
}

impl AugmentCliSettings {
    /// Resolves `auggie` without invoking a shell.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when the CLI is unavailable.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let executable = resolve_executable(
            "auggie",
            environment.get(CLI_OVERRIDE).map(String::as_str),
            environment.get("PATH").map(String::as_str).map(OsStr::new),
            &[
                PathBuf::from("/usr/local/bin/auggie"),
                PathBuf::from("/usr/bin/auggie"),
            ],
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Ok(Self { executable })
    }
}

/// Native `Augment` CLI provider.
pub struct AugmentProvider {
    scope: AccountScope,
    settings: AugmentCliSettings,
}

impl AugmentProvider {
    /// Creates a provider bound to one account scope.
    #[must_use]
    pub fn new(scope: AccountScope, settings: AugmentCliSettings) -> Self {
        Self { scope, settings }
    }

    /// Parses a bounded `auggie account status` report.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error when credit totals are absent or contradictory.
    #[doc(hidden)]
    pub fn parse_report_at(
        scope: AccountScope,
        fetched_at: Timestamp,
        output: &str,
    ) -> Result<UsageSample, ClassifiedError> {
        normalize_report(scope, fetched_at, output)
    }
}

impl ProviderAdapter for AugmentProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Augment)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            if context.scope() != &self.scope {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            let request = SubprocessRequest::new(
                self.settings.executable.as_path(),
                ["account", "status"],
                Duration::from_secs(15),
                MAX_STDOUT_BYTES,
                MAX_STDERR_BYTES,
            )
            .map_err(classify_subprocess)?;
            let output = request
                .run(context.cancellation())
                .await
                .map_err(classify_subprocess)?;
            let text = std::str::from_utf8(output.stdout())
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            let fetched_at = system_timestamp()?;
            Self::parse_report_at(self.scope.clone(), fetched_at, text)
        })
    }
}

fn normalize_report(
    scope: AccountScope,
    fetched_at: Timestamp,
    output: &str,
) -> Result<UsageSample, ClassifiedError> {
    if output.len() > MAX_STDOUT_BYTES {
        return Err(parse_error());
    }
    let mut remaining = None;
    let mut used = None;
    let mut total = None;
    let mut billing_end = None;
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        let numbers = integer_tokens(line);
        if lower.contains("credits / month") || lower.contains("credits/month") {
            total = numbers.first().copied().or(total);
        }
        if lower.contains("credits remaining") && !lower.contains("billing cycle") {
            remaining = numbers.first().copied().or(remaining);
        }
        if lower.contains("remaining") && lower.contains("credits used") && numbers.len() >= 3 {
            remaining = Some(numbers[0]);
            used = Some(numbers[1]);
            total = Some(numbers[2]);
        }
        if lower.contains("billing cycle")
            && let Some((_, suffix)) = lower.split_once("ends")
        {
            billing_end = parse_calendar_date(suffix).or(billing_end);
        }
    }
    let total = total.filter(|value| *value > 0).ok_or_else(parse_error)?;
    let remaining = remaining.ok_or_else(parse_error)?.clamp(0, total);
    let used = used.unwrap_or(total - remaining).clamp(0, total);
    let percent = ratio_percent(used, total)?;
    let description = format!("{remaining} / {total} credits remaining");
    let primary = RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        None,
        billing_end,
        Some(BoundedText::new(description).map_err(|_| parse_error())?),
        None,
        false,
    )
    .map_err(|_| parse_error())?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .login_method(Some(format!("{total} credits/month")))?
        .provenance("augment", "auggie-cli")?
        .build()
}

fn integer_tokens(value: &str) -> Vec<i64> {
    value
        .split(|character: char| !character.is_ascii_digit() && character != ',')
        .filter(|token| !token.is_empty())
        .filter_map(|token| token.replace(',', "").parse().ok())
        .collect()
}

fn parse_calendar_date(value: &str) -> Option<Timestamp> {
    let token = value
        .split_whitespace()
        .find(|token| token.bytes().filter(|byte| *byte == b'/').count() == 2)?
        .trim_matches(|character: char| !character.is_ascii_digit() && character != '/');
    let mut components = token.split('/');
    let month = Month::try_from(components.next()?.parse::<u8>().ok()?).ok()?;
    let day = components.next()?.parse::<u8>().ok()?;
    let year = components.next()?.parse::<i32>().ok()?;
    if components.next().is_some() {
        return None;
    }
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Timestamp::new(date.with_time(Time::MIDNIGHT).assume_utc()).ok()
}

fn ratio_percent(numerator: i64, denominator: i64) -> Result<f64, ClassifiedError> {
    (Decimal::from(numerator) * Decimal::ONE_HUNDRED / Decimal::from(denominator))
        .to_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(parse_error)
}

fn classify_subprocess(error: SubprocessError) -> ClassifiedError {
    let kind = match error {
        SubprocessError::Spawn => ErrorKind::MissingCredential,
        SubprocessError::Cancelled | SubprocessError::Timeout => ErrorKind::Network,
        SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge
        | SubprocessError::OutputRead => ErrorKind::Parse,
        SubprocessError::InvalidConfiguration
        | SubprocessError::Wait
        | SubprocessError::NonZero { .. } => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
