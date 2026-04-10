//! Configuration for the service-hub-demo module.

use serde::Deserialize;
use std::collections::HashMap;

/// Module configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceHubDemoConfig {
    /// Static remote endpoints: `module_name` -> `base_url`.
    /// Used by the resolver for dev/test when `DirectoryClient` is not available.
    #[serde(default)]
    pub remote_endpoints: HashMap<String, String>,
}
