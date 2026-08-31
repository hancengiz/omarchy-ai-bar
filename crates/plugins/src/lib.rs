//! Sandboxed user-provider plugins backed by an embedded `QuickJS` runtime.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rquickjs::{Context, Runtime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Maximum UTF-8 plugin source size.
pub const MAX_PLUGIN_SOURCE_BYTES: usize = 1024 * 1024;
/// Maximum JSON result size.
pub const MAX_PLUGIN_RESULT_BYTES: usize = 1024 * 1024;
/// `QuickJS` heap limit.
pub const PLUGIN_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
/// `QuickJS` stack limit.
pub const PLUGIN_STACK_LIMIT_BYTES: usize = 2 * 1024 * 1024;
/// Synchronous evaluation watchdog.
pub const PLUGIN_EXECUTION_LIMIT: Duration = Duration::from_secs(20);

/// Validated public metadata exported by a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Canonical lowercase plugin identifier.
    pub id: String,
    /// Bounded human-readable provider name.
    pub name: String,
    /// Plugin contract version. Version 1 is currently supported.
    pub version: u32,
}

/// One bounded plugin evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginEvaluation {
    /// Validated plugin metadata.
    pub manifest: PluginManifest,
    /// JSON-compatible provider sample returned by `collect()`.
    pub sample: Value,
}

/// Stable sandbox or contract failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PluginError {
    /// Source is empty, non-UTF-8, or larger than one MiB.
    #[error("plugin source is invalid or exceeds its size limit")]
    InvalidSource,
    /// The embedded runtime could not be initialized.
    #[error("plugin runtime could not be initialized")]
    Runtime,
    /// JavaScript failed, exceeded a limit, or exported the wrong contract.
    #[error("plugin execution failed or exceeded a sandbox limit")]
    Execution,
    /// Exported metadata does not match the version-1 contract.
    #[error("plugin manifest is invalid")]
    Manifest,
    /// The serialized result exceeded one MiB.
    #[error("plugin result exceeds its size limit")]
    ResultTooLarge,
}

/// Evaluates one local script without Node, browser, module, file, network, or
/// process host APIs.
///
/// The script must assign `globalThis.omarchyAiBarPlugin` to an object with
/// `id`, `name`, `version: 1`, and a synchronous `collect()` function returning
/// JSON-compatible data.
///
/// # Errors
///
/// Returns a stable [`PluginError`] for invalid source, runtime setup,
/// watchdog, memory, stack, JavaScript, manifest, or output failures.
pub fn evaluate(source: &[u8]) -> Result<PluginEvaluation, PluginError> {
    if source.is_empty() || source.len() > MAX_PLUGIN_SOURCE_BYTES {
        return Err(PluginError::InvalidSource);
    }
    let source = std::str::from_utf8(source).map_err(|_| PluginError::InvalidSource)?;
    let runtime = Runtime::new().map_err(|_| PluginError::Runtime)?;
    runtime.set_memory_limit(PLUGIN_MEMORY_LIMIT_BYTES);
    runtime.set_max_stack_size(PLUGIN_STACK_LIMIT_BYTES);
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupt_witness = Arc::clone(&interrupted);
    runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupt_witness.load(Ordering::Acquire)
    })));
    let watchdog_witness = Arc::clone(&interrupted);
    let (watchdog_cancel, watchdog_wait) = mpsc::channel();
    let watchdog = thread::spawn(move || {
        if watchdog_wait.recv_timeout(PLUGIN_EXECUTION_LIMIT).is_err() {
            watchdog_witness.store(true, Ordering::Release);
        }
    });

    let context = Context::full(&runtime).map_err(|_| PluginError::Runtime)?;
    let wrapped = format!(
        "\"use strict\";\n{source}\nJSON.stringify((function () {{\n\
         const plugin = globalThis.omarchyAiBarPlugin;\n\
         if (!plugin || typeof plugin !== 'object' || typeof plugin.collect !== 'function') throw new Error('contract');\n\
         return {{ manifest: {{ id: plugin.id, name: plugin.name, version: plugin.version }}, sample: plugin.collect() }};\n\
         }})());"
    );
    let encoded = context
        .with(|context| context.eval::<String, _>(wrapped.as_bytes()))
        .map_err(|_| PluginError::Execution);
    let _cancelled = watchdog_cancel.send(());
    watchdog.join().map_err(|_| PluginError::Runtime)?;
    let encoded = encoded?;
    if encoded.len() > MAX_PLUGIN_RESULT_BYTES {
        return Err(PluginError::ResultTooLarge);
    }
    let evaluation: PluginEvaluation =
        serde_json::from_str(&encoded).map_err(|_| PluginError::Execution)?;
    validate_manifest(&evaluation.manifest)?;
    Ok(evaluation)
}

fn validate_manifest(manifest: &PluginManifest) -> Result<(), PluginError> {
    if manifest.version != 1
        || manifest.id.is_empty()
        || manifest.id.len() > 64
        || manifest.name.is_empty()
        || manifest.name.len() > 120
        || !manifest
            .id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !manifest
            .id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        || manifest.name.chars().any(char::is_control)
    {
        return Err(PluginError::Manifest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_the_version_one_contract_without_host_globals() {
        let result = evaluate(
            br#"
                globalThis.omarchyAiBarPlugin = {
                    id: "fixture-provider",
                    name: "Fixture Provider",
                    version: 1,
                    collect() {
                        return {
                            used_percent: 42,
                            node: typeof process,
                            browser: typeof window,
                            fetch: typeof fetch,
                            require: typeof require
                        };
                    }
                };
            "#,
        )
        .expect("evaluate plugin");
        assert_eq!(result.manifest.id, "fixture-provider");
        assert_eq!(result.sample["used_percent"], 42);
        for field in ["node", "browser", "fetch", "require"] {
            assert_eq!(result.sample[field], "undefined");
        }
    }

    #[test]
    fn rejects_oversize_source_and_invalid_manifest() {
        assert_eq!(
            evaluate(&vec![b'x'; MAX_PLUGIN_SOURCE_BYTES + 1]),
            Err(PluginError::InvalidSource)
        );
        assert_eq!(
            evaluate(
                br#"globalThis.omarchyAiBarPlugin = { id: "Bad", name: "Bad", version: 1, collect() { return {}; } };"#
            ),
            Err(PluginError::Manifest)
        );
    }
}
