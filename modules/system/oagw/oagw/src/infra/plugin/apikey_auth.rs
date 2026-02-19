use std::sync::Arc;

use crate::domain::credential::CredentialResolver;
use crate::domain::plugin::{AuthContext, AuthPlugin, PluginError};
use serde::Deserialize;

/// Configuration for the API key auth plugin.
#[derive(Debug, Deserialize)]
struct ApiKeyConfig {
    /// Header name to set (e.g. "Authorization", "X-API-Key").
    header: String,
    /// Prefix prepended to the secret value (e.g. "Bearer ").
    #[serde(default)]
    prefix: String,
    /// Secret reference to resolve (e.g. "cred://openai-key").
    secret_ref: String,
}

/// Auth plugin that resolves a secret reference and injects it as a header value.
pub struct ApiKeyAuthPlugin {
    credential_resolver: Arc<dyn CredentialResolver>,
}

impl ApiKeyAuthPlugin {
    #[must_use]
    pub fn new(credential_resolver: Arc<dyn CredentialResolver>) -> Self {
        Self {
            credential_resolver,
        }
    }
}

#[async_trait::async_trait]
impl AuthPlugin for ApiKeyAuthPlugin {
    async fn authenticate(&self, ctx: &mut AuthContext) -> Result<(), PluginError> {
        let config: ApiKeyConfig = serde_json::from_value(
            serde_json::to_value(&ctx.config)
                .map_err(|e| PluginError::Internal(format!("invalid apikey auth config: {e}")))?,
        )
        .map_err(|e| PluginError::Internal(format!("invalid apikey auth config: {e}")))?;

        let secret = self
            .credential_resolver
            .resolve(&config.secret_ref)
            .await
            .map_err(|_| PluginError::SecretNotFound(config.secret_ref.clone()))?;

        let value = format!("{}{}", config.prefix, secret.as_str());
        ctx.headers.insert(config.header.to_lowercase(), value);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::domain::plugin::{AuthContext, AuthPlugin, PluginError};
    use crate::infra::storage::credential_repo::InMemoryCredentialResolver;

    use super::*;

    fn make_config(header: &str, prefix: &str, secret_ref: &str) -> HashMap<String, String> {
        HashMap::from([
            ("header".into(), header.into()),
            ("prefix".into(), prefix.into()),
            ("secret_ref".into(), secret_ref.into()),
        ])
    }

    #[tokio::test]
    async fn injects_bearer_token() {
        let creds = Arc::new(InMemoryCredentialResolver::with_credentials(vec![(
            "cred://openai-key".into(),
            "sk-abc123".into(),
        )]));
        let plugin = ApiKeyAuthPlugin::new(creds);

        let mut ctx = AuthContext {
            headers: HashMap::new(),
            config: make_config("authorization", "Bearer ", "cred://openai-key"),
        };

        plugin.authenticate(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.headers.get("authorization").unwrap(),
            "Bearer sk-abc123"
        );
    }

    #[tokio::test]
    async fn injects_custom_header_no_prefix() {
        let creds = Arc::new(InMemoryCredentialResolver::with_credentials(vec![(
            "cred://custom-key".into(),
            "my-secret-key".into(),
        )]));
        let plugin = ApiKeyAuthPlugin::new(creds);

        let mut ctx = AuthContext {
            headers: HashMap::new(),
            config: make_config("x-api-key", "", "cred://custom-key"),
        };

        plugin.authenticate(&mut ctx).await.unwrap();
        assert_eq!(ctx.headers.get("x-api-key").unwrap(), "my-secret-key");
    }

    #[tokio::test]
    async fn secret_not_found_returns_error() {
        let creds = Arc::new(InMemoryCredentialResolver::new());
        let plugin = ApiKeyAuthPlugin::new(creds);

        let mut ctx = AuthContext {
            headers: HashMap::new(),
            config: make_config("authorization", "Bearer ", "cred://missing"),
        };

        let err = plugin.authenticate(&mut ctx).await.unwrap_err();
        assert!(matches!(err, PluginError::SecretNotFound(_)));
    }
}
