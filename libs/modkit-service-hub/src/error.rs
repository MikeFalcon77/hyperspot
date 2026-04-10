//! Error types for the service hub framework.

/// Errors that can occur during service hub operations.
#[derive(Debug, thiserror::Error)]
pub enum ServiceHubError {
    /// Service not found in registry or discovery.
    #[error("service not found: {service}")]
    ServiceNotFound {
        /// The service name that was not found.
        service: String,
    },

    /// No factory registered for the requested service type.
    #[error("no factory registered for type: {type_key}")]
    NoFactory {
        /// The type key that has no registered factory.
        type_key: String,
    },

    /// Resolution failed (resolver could not determine target).
    #[error("resolution failed for {service}: {reason}")]
    ResolutionFailed {
        /// The service name for which resolution failed.
        service: String,
        /// The reason resolution failed.
        reason: String,
    },

    /// Transport-level error during remote call.
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Client hub error (type not found or mismatch).
    #[error("client hub error: {0}")]
    ClientHub(String),

    /// IR validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// Timeout exceeded.
    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}
