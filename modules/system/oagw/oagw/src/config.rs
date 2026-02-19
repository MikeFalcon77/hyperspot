use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Configuration for the OAGW module.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OagwConfig {
    #[serde(default = "default_proxy_timeout_secs")]
    pub proxy_timeout_secs: u64,
    #[serde(default = "default_max_body_size_bytes")]
    pub max_body_size_bytes: usize,
    /// Optional credentials to pre-load into the in-memory credential resolver.
    /// Keys are secret references (e.g., `cred://openai-key`), values are secrets.
    /// Intended for development and testing only.
    #[serde(default)]
    pub credentials: HashMap<String, String>,
}

impl Default for OagwConfig {
    fn default() -> Self {
        Self {
            proxy_timeout_secs: default_proxy_timeout_secs(),
            max_body_size_bytes: default_max_body_size_bytes(),
            credentials: HashMap::new(),
        }
    }
}

fn default_proxy_timeout_secs() -> u64 {
    30
}

fn default_max_body_size_bytes() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// Read-only runtime configuration exposed to handlers via `AppState`.
///
/// Derived from [`OagwConfig`] at init time, excluding sensitive fields
/// like credentials that are only needed during bootstrap.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub max_body_size_bytes: usize,
}

impl From<&OagwConfig> for RuntimeConfig {
    fn from(cfg: &OagwConfig) -> Self {
        Self {
            max_body_size_bytes: cfg.max_body_size_bytes,
        }
    }
}

impl fmt::Debug for OagwConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OagwConfig")
            .field("proxy_timeout_secs", &self.proxy_timeout_secs)
            .field("max_body_size_bytes", &self.max_body_size_bytes)
            .field(
                "credentials",
                &self
                    .credentials
                    .keys()
                    .map(|k| (k.as_str(), "[REDACTED]"))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_credentials() {
        let mut config = OagwConfig::default();
        config
            .credentials
            .insert("cred://openai-key".into(), "sk-secret-value-12345".into());

        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("sk-secret-value-12345"),
            "Debug output must not contain credential values"
        );
        assert!(debug_output.contains("cred://openai-key"));
        assert!(debug_output.contains("[REDACTED]"));
    }
}
