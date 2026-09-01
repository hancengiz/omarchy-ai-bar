//! First-party provider implementations.

pub mod browser_cookie;
pub mod browser_profile;
pub mod capability;
pub mod chromium_crypto;
pub mod chromium_leveldb;
pub mod cloud_signing;
pub mod configured_endpoint;
pub mod context;
pub mod cookie;
pub mod descriptor;
pub mod endpoint;
pub mod executable;
pub mod fixed_api;
pub mod json_rpc_child;
pub mod manual_capture;
pub mod normalize;
pub mod provider_files;
pub mod providers;
pub mod redaction;
pub mod registry;
pub mod retry;
pub mod settings_descriptor;
pub mod sqlite_snapshot;
pub mod subprocess;
pub mod transport;
