//! `Windsurf` Linux local-state usage adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rusqlite::types::ValueRef;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};

const DATA_DIR_ENV: &str = "WINDSURF_DATA_DIR";
const DATABASE_NAME: &str = "state.vscdb";
const PLAN_KEY: &str = "windsurf.settings.cachedPlanInfo";
const MAX_VALUE_BYTES: usize = 2 * 1024 * 1024;

/// Resolved Linux Windsurf global-storage directory.
pub struct WindsurfSettings {
    profile_root: PathBuf,
}

impl WindsurfSettings {
    /// Resolves the Omarchy/Linux Windsurf storage directory.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when no safe absolute path can be derived.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let profile_root = if let Some(value) = environment
            .get(DATA_DIR_ENV)
            .and_then(|value| clean_setting(value))
        {
            PathBuf::from(value)
        } else if let Some(value) = environment
            .get("XDG_CONFIG_HOME")
            .and_then(|value| clean_setting(value))
        {
            PathBuf::from(value).join("Windsurf/User/globalStorage")
        } else {
            let home = environment
                .get("HOME")
                .and_then(|value| clean_setting(value))
                .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
            PathBuf::from(home).join(".config/Windsurf/User/globalStorage")
        };
        if !profile_root.is_absolute() || profile_root.as_os_str().as_encoded_bytes().len() > 4096 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { profile_root })
    }

    /// Creates settings for an explicit fixture root.
    #[doc(hidden)]
    pub fn for_profile_root(profile_root: PathBuf) -> Result<Self, ClassifiedError> {
        if !profile_root.is_absolute() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { profile_root })
    }
}

impl Debug for WindsurfSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindsurfSettings")
            .field("profile_root", &"<redacted>")
            .finish()
    }
}

/// Native `Windsurf` provider for the Linux VS Code-compatible state database.
pub struct WindsurfProvider {
    scope: AccountScope,
    settings: WindsurfSettings,
}

impl WindsurfProvider {
    /// Creates a provider bound to one account scope.
    #[must_use]
    pub fn new(scope: AccountScope, settings: WindsurfSettings) -> Self {
        Self { scope, settings }
    }

    /// Reads one stable, private SQLite snapshot and normalizes cached plan state.
    ///
    /// # Errors
    ///
    /// Returns stable missing-data, SQLite, and parse errors without exposing paths.
    #[doc(hidden)]
    pub fn read_at(&self, fetched_at: Timestamp) -> Result<UsageSample, ClassifiedError> {
        let snapshot = ReadOnlySqliteSnapshot::open(&self.settings.profile_root, DATABASE_NAME)
            .map_err(classify_sqlite)?;
        let mut statement = snapshot
            .connection()
            .prepare("SELECT value FROM ItemTable WHERE key = ?1 LIMIT 1")
            .map_err(|_| parse_error())?;
        let mut rows = statement.query([PLAN_KEY]).map_err(|_| parse_error())?;
        let row = rows
            .next()
            .map_err(|_| parse_error())?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let raw = row.get_ref(0).map_err(|_| parse_error())?;
        let bytes = match raw {
            ValueRef::Text(value) | ValueRef::Blob(value) => value,
            ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) => return Err(parse_error()),
        };
        if bytes.len() > MAX_VALUE_BYTES {
            return Err(parse_error());
        }
        let text = decode_json_bytes(bytes).ok_or_else(parse_error)?;
        let payload: CachedPlan = serde_json::from_str(&text).map_err(|_| parse_error())?;
        normalize(self.scope.clone(), fetched_at, payload)
    }
}

impl ProviderAdapter for WindsurfProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Windsurf)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            if context.scope() != &self.scope || context.source() != ProviderSource::LocalData {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            self.read_at(system_timestamp()?)
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedPlan {
    plan_name: Option<String>,
    end_timestamp: Option<i64>,
    usage: Option<Usage>,
    quota_usage: Option<QuotaUsage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Usage {
    messages: Option<i64>,
    used_messages: Option<i64>,
    remaining_messages: Option<i64>,
    flow_actions: Option<i64>,
    used_flow_actions: Option<i64>,
    remaining_flow_actions: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuotaUsage {
    daily_remaining_percent: Option<f64>,
    weekly_remaining_percent: Option<f64>,
    daily_reset_at_unix: Option<i64>,
    weekly_reset_at_unix: Option<i64>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: CachedPlan,
) -> Result<UsageSample, ClassifiedError> {
    let quota = payload.quota_usage.as_ref();
    let mut primary = quota
        .and_then(|value| value.daily_remaining_percent)
        .map(|remaining| {
            remaining_window(remaining, quota.and_then(|value| value.daily_reset_at_unix))
        })
        .transpose()?;
    let mut secondary = quota
        .and_then(|value| value.weekly_remaining_percent)
        .map(|remaining| {
            remaining_window(
                remaining,
                quota.and_then(|value| value.weekly_reset_at_unix),
            )
        })
        .transpose()?;
    if let Some(usage) = payload.usage.as_ref() {
        if primary.is_none() {
            primary = count_window(
                usage.used_messages,
                usage.remaining_messages,
                usage.messages,
                "messages",
            )?;
        }
        if secondary.is_none() {
            secondary = count_window(
                usage.used_flow_actions,
                usage.remaining_flow_actions,
                usage.flow_actions,
                "flow actions",
            )?;
        }
    }
    if primary.is_none() && secondary.is_none() {
        return Err(parse_error());
    }
    let expires_at = payload
        .end_timestamp
        .and_then(|value| Timestamp::from_unix_timestamp(value / 1_000).ok());
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(payload.plan_name)?
        .subscription_expires_at(expires_at);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("windsurf", "linux-local-state")?.build()
}

fn remaining_window(remaining: f64, reset: Option<i64>) -> Result<RateWindow, ClassifiedError> {
    if !remaining.is_finite() {
        return Err(parse_error());
    }
    let used = (100.0 - remaining).clamp(0.0, 100.0);
    window(
        used,
        reset.and_then(|value| Timestamp::from_unix_timestamp(value).ok()),
        None,
    )
}

fn count_window(
    raw_used: Option<i64>,
    raw_remaining: Option<i64>,
    raw_total: Option<i64>,
    unit: &str,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let Some(total) = raw_total.filter(|value| *value > 0) else {
        return Ok(None);
    };
    let Some(used) = raw_used.or_else(|| raw_remaining.map(|value| total - value)) else {
        return Ok(None);
    };
    let used = used.clamp(0, total);
    let percent = (Decimal::from(used) * Decimal::ONE_HUNDRED / Decimal::from(total))
        .to_f64()
        .ok_or_else(parse_error)?;
    let description =
        BoundedText::new(format!("{used} / {total} {unit}")).map_err(|_| parse_error())?;
    window(percent, None, Some(description)).map(Some)
}

fn window(
    percent: f64,
    reset: Option<Timestamp>,
    description: Option<BoundedText<120>>,
) -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        None,
        reset,
        description,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn decode_json_bytes(bytes: &[u8]) -> Option<String> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim_matches(char::from(0));
        if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            return Some(trimmed.to_owned());
        }
    }
    if bytes.len().is_multiple_of(2) {
        let (pairs, remainder) = bytes.as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        let units = pairs
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        let text = String::from_utf16(&units).ok()?;
        let trimmed = text.trim_matches(char::from(0));
        if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            return Some(trimmed.to_owned());
        }
    }
    None
}

fn classify_sqlite(error: SqliteSnapshotError) -> ClassifiedError {
    ClassifiedError::new(match error {
        SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot => {
            ErrorKind::MissingCredential
        }
        SqliteSnapshotError::Replaced => ErrorKind::ProviderUnavailable,
        SqliteSnapshotError::InvalidRelativePath
        | SqliteSnapshotError::UnsafeFile
        | SqliteSnapshotError::TooLarge
        | SqliteSnapshotError::Open
        | SqliteSnapshotError::Configure
        | SqliteSnapshotError::Snapshot => ErrorKind::Parse,
    })
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
