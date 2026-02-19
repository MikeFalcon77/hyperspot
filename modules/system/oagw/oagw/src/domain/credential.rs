use modkit_macros::domain_model;

/// The resolved secret material.
#[domain_model]
#[derive(Clone)]
pub(crate) struct SecretValue {
    value: String,
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl SecretValue {
    #[must_use]
    pub(crate) fn new(value: String) -> Self {
        Self { value }
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }
}

/// Intentionally does not display the secret value.
impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_debug_redacts() {
        let secret = SecretValue::new("super-secret-key-12345".into());
        let debug_output = format!("{secret:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super-secret-key-12345"));
    }

    #[test]
    fn secret_value_display_redacts() {
        let secret = SecretValue::new("another-secret".into());
        let display_output = format!("{secret}");
        assert_eq!(display_output, "[REDACTED]");
    }
}

/// Errors from credential resolution.
#[domain_model]
#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialError {
    #[error("credential not found: {0}")]
    NotFound(String),
    #[error("credential error: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

/// Trait for resolving secret references to their actual values.
#[async_trait::async_trait]
pub(crate) trait CredentialResolver: Send + Sync {
    /// Resolve a secret reference (e.g. `cred://openai-key`) to its value.
    ///
    /// # Errors
    /// Returns `CredentialError::NotFound` if the reference does not exist.
    async fn resolve(&self, secret_ref: &str) -> Result<SecretValue, CredentialError>;
}
