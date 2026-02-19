use std::collections::HashMap;

use modkit_macros::domain_model;

// ---------------------------------------------------------------------------
// Plugin errors
// ---------------------------------------------------------------------------

#[domain_model]
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("authentication failed: {0}")]
    #[allow(dead_code)] // Part of plugin trait API; no current plugin constructs this.
    AuthFailed(String),
    #[error("request rejected: {0}")]
    #[allow(dead_code)] // Part of plugin trait API; no current plugin constructs this.
    Rejected(String),
    #[error("plugin error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Auth plugin
// ---------------------------------------------------------------------------

#[domain_model]
pub struct AuthContext {
    pub headers: HashMap<String, String>,
    pub config: HashMap<String, String>,
}

#[async_trait::async_trait]
pub trait AuthPlugin: Send + Sync {
    async fn authenticate(&self, ctx: &mut AuthContext) -> Result<(), PluginError>;
}
