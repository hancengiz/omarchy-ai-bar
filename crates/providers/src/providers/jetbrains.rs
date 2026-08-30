//! Read-only `JetBrains` AI quota discovery for Linux IDE configuration roots.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
};
use serde_json::Value;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;

const IDE_PATH_OVERRIDE: &str = "OMARCHY_AI_BAR_JETBRAINS_IDE_PATH";
const QUOTA_FILE_NAME: &str = "AIAssistantQuotaManager2.xml";
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_DIRECTORY_NAME_BYTES: usize = 255;
const MAX_XML_BYTES: u64 = 1024 * 1024;
const MAX_TAG_BYTES: usize = 256 * 1024;
const MAX_ATTRIBUTE_BYTES: usize = 128 * 1024;
const MAX_OPTIONS: usize = 512;
const MAX_JSON_BYTES: usize = 128 * 1024;
const MAX_IDENTITY_BYTES: usize = 256;

const IDE_PATTERNS: [(&str, &str); 16] = [
    ("IntelliJIdea", "IntelliJ IDEA"),
    ("IdeaIC", "IntelliJ IDEA Community"),
    ("IdeaIU", "IntelliJ IDEA Ultimate"),
    ("PyCharm", "PyCharm"),
    ("WebStorm", "WebStorm"),
    ("GoLand", "GoLand"),
    ("CLion", "CLion"),
    ("DataGrip", "DataGrip"),
    ("RubyMine", "RubyMine"),
    ("Rider", "Rider"),
    ("PhpStorm", "PhpStorm"),
    ("Fleet", "Fleet"),
    ("AndroidStudio", "Android Studio"),
    ("RustRover", "RustRover"),
    ("Aqua", "Aqua"),
    ("DataSpell", "DataSpell"),
];

/// Validated Linux roots used for `JetBrains` IDE quota discovery.
#[derive(Clone)]
pub struct JetBrainsSettings {
    explicit_ide_path: Option<PathBuf>,
    discovery_roots: Vec<PathBuf>,
}

impl JetBrainsSettings {
    /// Resolves an optional application override and standard XDG roots.
    ///
    /// `OMARCHY_AI_BAR_JETBRAINS_IDE_PATH` names one IDE configuration
    /// directory. Otherwise discovery checks `JetBrains` and Google directories
    /// below `XDG_CONFIG_HOME` and `JetBrains` below `XDG_DATA_HOME`, with the
    /// standard `$HOME/.config` and `$HOME/.local/share` fallbacks.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for relative, empty, or oversized paths.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        if let Some(path) = environment
            .get(IDE_PATH_OVERRIDE)
            .and_then(|value| clean_setting(value))
        {
            return Self::from_ide_path(path);
        }

        let home = required_absolute_path(environment, "HOME")?;
        let config_home = optional_absolute_path(environment, "XDG_CONFIG_HOME")?
            .unwrap_or_else(|| home.join(".config"));
        let data_home = optional_absolute_path(environment, "XDG_DATA_HOME")?
            .unwrap_or_else(|| home.join(".local/share"));
        let roots = vec![
            config_home.join("JetBrains"),
            data_home.join("JetBrains"),
            config_home.join("Google"),
        ];
        for root in &roots {
            validate_absolute_path(root)?;
        }
        Ok(Self {
            explicit_ide_path: None,
            discovery_roots: roots,
        })
    }

    /// Creates settings for one explicit IDE configuration directory.
    ///
    /// # Errors
    ///
    /// Returns a stable API error unless the path is absolute and bounded.
    pub fn from_ide_path(path: impl Into<PathBuf>) -> Result<Self, ClassifiedError> {
        let path = path.into();
        validate_absolute_path(&path)?;
        Ok(Self {
            explicit_ide_path: Some(path),
            discovery_roots: Vec::new(),
        })
    }

    /// Creates a deterministic discovery-root set for integration tests.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an empty, excessive, or unsafe set.
    #[doc(hidden)]
    pub fn from_discovery_roots(
        roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, ClassifiedError> {
        let roots = roots.into_iter().collect::<Vec<_>>();
        if roots.is_empty() || roots.len() > 8 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        for root in &roots {
            validate_absolute_path(root)?;
        }
        Ok(Self {
            explicit_ide_path: None,
            discovery_roots: roots,
        })
    }
}

impl Debug for JetBrainsSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JetBrainsSettings")
            .field("has_explicit_ide_path", &self.explicit_ide_path.is_some())
            .field("discovery_root_count", &self.discovery_roots.len())
            .finish()
    }
}

/// Non-sensitive IDE identity projected from a configuration directory name.
#[derive(Clone, PartialEq, Eq)]
pub struct JetBrainsIdeInfo {
    name: String,
    version: String,
    base_path: PathBuf,
    quota_path: PathBuf,
}

impl JetBrainsIdeInfo {
    /// Human-readable IDE family.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Version suffix from the IDE configuration directory.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// IDE family and version without a filesystem path.
    #[must_use]
    pub fn display_name(&self) -> String {
        format!("{} {}", self.name, self.version)
    }

    /// Absolute IDE configuration directory.
    #[must_use]
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Absolute quota document selected below the IDE directory.
    #[must_use]
    pub fn quota_path(&self) -> &Path {
        &self.quota_path
    }
}

impl Debug for JetBrainsIdeInfo {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JetBrainsIdeInfo")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("base_path", &"<redacted>")
            .field("quota_path", &"<redacted>")
            .finish()
    }
}

/// Native Linux `JetBrains` AI local quota adapter.
pub struct JetBrainsProvider {
    scope: AccountScope,
    settings: JetBrainsSettings,
}

impl JetBrainsProvider {
    /// Creates an account-bound read-only provider.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for a scope belonging to another provider.
    pub fn new(scope: AccountScope, settings: JetBrainsSettings) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::JetBrains {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { scope, settings })
    }

    /// Reads and normalizes one bounded quota document.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential, API, or parse categories. Filesystem
    /// paths and document contents are never attached to the public error.
    pub fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let selected = resolve_quota_file(&self.settings)?;
        let bytes = read_bounded_file(&selected.path, MAX_XML_BYTES)?;
        let parsed = parse_document(&bytes)?;
        normalize(
            context.scope().clone(),
            fetched_at,
            selected.ide.as_ref(),
            parsed,
        )
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::LocalData {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(())
    }
}

impl Debug for JetBrainsProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JetBrainsProvider")
            .field("scope", &self.scope)
            .field("settings", &self.settings)
            .finish()
    }
}

impl ProviderAdapter for JetBrainsProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::JetBrains)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            self.validate_context(context)?;
            if context.cancellation().is_cancelled() {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            let cancellation = context.cancellation().clone();
            let scope = self.scope.clone();
            let settings = self.settings.clone();
            let blocking_context = context.clone();
            let mut task = tokio::task::spawn_blocking(move || {
                let provider = Self { scope, settings };
                let fetched_at = system_timestamp()?;
                provider.fetch_at(&blocking_context, fetched_at)
            });
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    task.abort();
                    Err(ClassifiedError::new(ErrorKind::Network))
                }
                result = &mut task => {
                    result.unwrap_or_else(|_| Err(ClassifiedError::new(ErrorKind::Api)))
                }
            }
        })
    }
}

struct SelectedQuota {
    path: PathBuf,
    ide: Option<JetBrainsIdeInfo>,
}

fn resolve_quota_file(settings: &JetBrainsSettings) -> Result<SelectedQuota, ClassifiedError> {
    if let Some(base_path) = &settings.explicit_ide_path {
        let path = quota_path(base_path)?;
        return Ok(SelectedQuota { path, ide: None });
    }

    let mut candidates = Vec::<(SystemTime, JetBrainsIdeInfo)>::new();
    let mut inspected = 0_usize;
    for root in &settings.discovery_roots {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        };
        for entry in entries {
            inspected = inspected
                .checked_add(1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            if inspected > MAX_DIRECTORY_ENTRIES {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            let Ok(entry) = entry else { continue };
            let Some(dirname) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(ide) = parse_ide_directory(&dirname, root)? else {
                continue;
            };
            let metadata = match fs::symlink_metadata(&ide.quota_path) {
                Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_XML_BYTES => metadata,
                _ => continue,
            };
            candidates.push((metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH), ide));
        }
    }
    candidates.sort_by(|(left_time, left), (right_time, right)| {
        right_time
            .cmp(left_time)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| compare_versions(&right.version, &left.version))
    });
    let (_, ide) = candidates
        .into_iter()
        .next()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    Ok(SelectedQuota {
        path: ide.quota_path.clone(),
        ide: Some(ide),
    })
}

fn parse_ide_directory(
    dirname: &str,
    root: &Path,
) -> Result<Option<JetBrainsIdeInfo>, ClassifiedError> {
    if dirname.is_empty()
        || dirname.len() > MAX_DIRECTORY_NAME_BYTES
        || dirname.chars().any(char::is_control)
    {
        return Ok(None);
    }
    for (prefix, display_name) in IDE_PATTERNS {
        if dirname.len() < prefix.len()
            || !dirname.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        {
            continue;
        }
        let suffix = dirname[prefix.len()..].trim();
        let version = if suffix.is_empty() { "Unknown" } else { suffix };
        if version.len() > 64 || version.chars().any(char::is_control) {
            return Ok(None);
        }
        let base_path = root.join(dirname);
        validate_absolute_path(&base_path)?;
        let quota_path = quota_path(&base_path)?;
        return Ok(Some(JetBrainsIdeInfo {
            name: display_name.to_owned(),
            version: version.to_owned(),
            base_path,
            quota_path,
        }));
    }
    Ok(None)
}

fn quota_path(base: &Path) -> Result<PathBuf, ClassifiedError> {
    let path = base.join("options").join(QUOTA_FILE_NAME);
    validate_absolute_path(&path)?;
    Ok(path)
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect::<Vec<_>>();
    let right = right
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect::<Vec<_>>();
    let len = left.len().max(right.len());
    (0..len)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&right.get(index).copied().unwrap_or(0))
        })
        .find(|ordering| !ordering.is_eq())
        .unwrap_or(std::cmp::Ordering::Equal)
}

struct ParsedDocument {
    quota: ParsedQuota,
    refill: Option<ParsedRefill>,
}

struct ParsedQuota {
    kind: Option<String>,
    used: f64,
    maximum: f64,
    available: f64,
    until: Option<Timestamp>,
}

struct ParsedRefill {
    kind: Option<String>,
    next: Option<Timestamp>,
    amount: Option<f64>,
    duration: Option<String>,
}

fn parse_document(bytes: &[u8]) -> Result<ParsedDocument, ClassifiedError> {
    if bytes.len() as u64 > MAX_XML_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let xml = std::str::from_utf8(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let component = component_body(xml)?;
    let mut quota_raw = None;
    let mut refill_raw = None;
    let mut offset = 0_usize;
    let mut options = 0_usize;
    while let Some(relative) = component[offset..].find("<option") {
        options += 1;
        if options > MAX_OPTIONS {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let start = offset + relative;
        let end = tag_end(component.as_bytes(), start)?;
        if end - start > MAX_TAG_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let tag = &component[start..=end];
        let name = attribute_value(tag, "name")?;
        if name.as_deref() == Some("quotaInfo") && quota_raw.is_none() {
            quota_raw = attribute_value(tag, "value")?;
        } else if name.as_deref() == Some("nextRefill") && refill_raw.is_none() {
            refill_raw = attribute_value(tag, "value")?;
        }
        offset = end + 1;
    }
    let quota_raw = quota_raw
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let quota_json = decode_xml_entities(&quota_raw);
    if quota_json.len() > MAX_JSON_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let quota = parse_quota_json(&quota_json)?;
    let refill = refill_raw
        .filter(|value| !value.is_empty())
        .map(|value| decode_xml_entities(&value))
        .filter(|value| value.len() <= MAX_JSON_BYTES)
        .and_then(|value| parse_refill_json(&value).ok());
    Ok(ParsedDocument { quota, refill })
}

fn component_body(xml: &str) -> Result<&str, ClassifiedError> {
    let mut offset = 0_usize;
    while let Some(relative) = xml[offset..].find("<component") {
        let start = offset + relative;
        let end = tag_end(xml.as_bytes(), start)?;
        if end - start > MAX_TAG_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let tag = &xml[start..=end];
        if attribute_value(tag, "name")?.as_deref() == Some("AIAssistantQuotaManager2") {
            let body_start = end + 1;
            let close = xml[body_start..]
                .find("</component>")
                .map(|relative| body_start + relative)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            return Ok(&xml[body_start..close]);
        }
        offset = end + 1;
    }
    Err(ClassifiedError::new(ErrorKind::MissingCredential))
}

fn tag_end(bytes: &[u8], start: usize) -> Result<usize, ClassifiedError> {
    let mut quote = None;
    for (index, byte) in bytes.iter().copied().enumerate().skip(start) {
        match (quote, byte) {
            (None, b'\'' | b'"') => quote = Some(byte),
            (Some(open), close) if open == close => quote = None,
            (None, b'>') => return Ok(index),
            _ => {}
        }
        if index.saturating_sub(start) > MAX_TAG_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn attribute_value(tag: &str, wanted: &str) -> Result<Option<String>, ClassifiedError> {
    let bytes = tag.as_bytes();
    let mut index = tag.find(char::is_whitespace).unwrap_or(tag.len());
    let mut attributes = 0_usize;
    while index < bytes.len() {
        while index < bytes.len()
            && (bytes[index].is_ascii_whitespace() || matches!(bytes[index], b'/' | b'>'))
        {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        attributes += 1;
        if attributes > 64 {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let name_start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-' | b':'))
        {
            index += 1;
        }
        if index == name_start {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let name = &tag[name_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let Some(delimiter @ (b'\'' | b'"')) = bytes.get(index).copied() else {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        };
        index += 1;
        let value_start = index;
        while index < bytes.len() && bytes[index] != delimiter {
            index += 1;
        }
        if index == bytes.len() || index - value_start > MAX_ATTRIBUTE_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        if name == wanted {
            return Ok(Some(tag[value_start..index].to_owned()));
        }
        index += 1;
    }
    Ok(None)
}

fn decode_xml_entities(value: &str) -> String {
    value
        .replace("&#10;", "\n")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_quota_json(value: &str) -> Result<ParsedQuota, ClassifiedError> {
    let value: Value = serde_json::from_str(value).map_err(parse_error)?;
    let object = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if object.len() > 32 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let kind = optional_identity(object.get("type"))?;
    let used = optional_number_string(object.get("current"))?.unwrap_or(0.0);
    let maximum = optional_number_string(object.get("maximum"))?.unwrap_or(0.0);
    let available = match object.get("tariffQuota") {
        None | Some(Value::Null) => None,
        Some(Value::Object(tariff)) if tariff.len() <= 16 => {
            optional_number_string(tariff.get("available"))?
        }
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    }
    .unwrap_or_else(|| (maximum - used).max(0.0));
    let until = optional_timestamp_string(object.get("until"))?;
    Ok(ParsedQuota {
        kind,
        used,
        maximum,
        available,
        until,
    })
}

fn parse_refill_json(value: &str) -> Result<ParsedRefill, ClassifiedError> {
    let value: Value = serde_json::from_str(value).map_err(parse_error)?;
    let object = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if object.len() > 32 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let tariff = match object.get("tariff") {
        None | Some(Value::Null) => None,
        Some(Value::Object(tariff)) if tariff.len() <= 16 => Some(tariff),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let amount = optional_number_string(object.get("amount"))?.or(optional_number_string(
        tariff.and_then(|value| value.get("amount")),
    )?);
    let duration = optional_identity(object.get("duration"))?.or(optional_identity(
        tariff.and_then(|value| value.get("duration")),
    )?);
    Ok(ParsedRefill {
        kind: optional_identity(object.get("type"))?,
        next: optional_timestamp_string(object.get("next"))?,
        amount,
        duration,
    })
}

fn optional_number_string(value: Option<&Value>) -> Result<Option<f64>, ClassifiedError> {
    match value {
        Some(Value::String(value)) if value.len() <= 128 => Ok(value
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite())),
        Some(Value::String(_)) => Err(ClassifiedError::new(ErrorKind::Parse)),
        _ => Ok(None),
    }
}

fn optional_identity(value: Option<&Value>) -> Result<Option<String>, ClassifiedError> {
    match value {
        Some(Value::String(value)) => {
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            if value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            Ok(Some(value.to_owned()))
        }
        _ => Ok(None),
    }
}

fn optional_timestamp_string(value: Option<&Value>) -> Result<Option<Timestamp>, ClassifiedError> {
    match value {
        Some(Value::String(value)) if value.len() <= 128 => Ok(Timestamp::parse(value).ok()),
        Some(Value::String(_)) => Err(ClassifiedError::new(ErrorKind::Parse)),
        _ => Ok(None),
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    ide: Option<&JetBrainsIdeInfo>,
    document: ParsedDocument,
) -> Result<UsageSample, ClassifiedError> {
    let used_percent = if document.quota.maximum > 0.0 {
        (document.quota.used / document.quota.maximum * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    if !used_percent.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let reset = document.refill.as_ref().and_then(|refill| refill.next);
    let description = reset
        .map(|reset| reset_description(reset, fetched_at))
        .map(BoundedText::new)
        .transpose()
        .map_err(parse_error)?;
    let primary = RateWindow::new(
        WindowUsage::known(UsagePercent::new(used_percent).map_err(parse_error)?),
        None,
        reset,
        description,
        None,
        false,
    )
    .map_err(parse_error)?;

    let mut rows = vec![
        detail_row("Credits used", format_number(document.quota.used))?,
        detail_row("Credits maximum", format_number(document.quota.maximum))?,
        detail_row("Credits available", format_number(document.quota.available))?,
    ];
    if let Some(until) = document.quota.until {
        rows.push(detail_row("Quota valid until", until.to_string())?);
    }
    if let Some(refill) = &document.refill {
        if let Some(kind) = &refill.kind {
            rows.push(detail_row("Refill type", kind.clone())?);
        }
        if let Some(amount) = refill.amount {
            rows.push(detail_row("Refill amount", format_number(amount))?);
        }
        if let Some(duration) = &refill.duration {
            rows.push(detail_row("Refill duration", duration.clone())?);
        }
    }
    if let Some(ide) = ide {
        rows.push(detail_row("IDE", ide.display_name())?);
    }
    let details = DetailSection::new(Some("JetBrains AI quota".to_owned()), rows, None)
        .map_err(parse_error)?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .organization(ide.map(JetBrainsIdeInfo::display_name))?
        .login_method(document.quota.kind)?
        .detail_sections(vec![details])
        .provenance("jetbrains", "local")?
        .build()
}

fn reset_description(reset: Timestamp, fetched_at: Timestamp) -> String {
    let seconds = reset
        .unix_timestamp()
        .saturating_sub(fetched_at.unix_timestamp());
    if seconds <= 0 {
        return "Expired".to_owned();
    }
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours >= 24 {
        format!("Resets in {}d {}h", hours / 24, hours % 24)
    } else if hours > 0 {
        format!("Resets in {hours}h {minutes}m")
    } else {
        format!("Resets in {minutes}m")
    }
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_992.0 {
        format!("{value:.0}")
    } else if value.abs() >= 1_000_000_000_000_000.0 || (value != 0.0 && value.abs() < 0.0001) {
        format!("{value:.6e}")
    } else {
        let value = format!("{value:.4}");
        value.trim_end_matches('0').trim_end_matches('.').to_owned()
    }
}

fn detail_row(label: &str, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Public).map_err(parse_error)
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, ClassifiedError> {
    validate_absolute_path(path)?;
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let metadata = file
        .metadata()
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if bytes.len() as u64 > limit {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(bytes)
}

fn required_absolute_path(
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<PathBuf, ClassifiedError> {
    environment
        .get(name)
        .and_then(|value| clean_setting(value))
        .map(PathBuf::from)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))
        .and_then(|path| {
            validate_absolute_path(&path)?;
            Ok(path)
        })
}

fn optional_absolute_path(
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<PathBuf>, ClassifiedError> {
    environment
        .get(name)
        .and_then(|value| clean_setting(value))
        .map(PathBuf::from)
        .map(|path| {
            validate_absolute_path(&path)?;
            Ok(path)
        })
        .transpose()
}

fn validate_absolute_path(path: &Path) -> Result<(), ClassifiedError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0)
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
