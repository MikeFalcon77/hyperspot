//! Configuration for the api-contracts module.

use serde::Deserialize;
use std::collections::HashMap;

/// Module configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiContractsConfig {
    /// Static remote REST endpoints: `module_name` -> `base_url`.
    #[serde(default)]
    pub remote_endpoints: HashMap<String, String>,
    /// Static remote gRPC endpoints: `module_name` -> `base_url`.
    /// When set for this module, the gRPC client takes precedence over REST.
    #[serde(default)]
    pub remote_grpc_endpoints: HashMap<String, String>,
}
