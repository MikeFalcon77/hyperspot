//! Transport binding types for resolved service locations.

/// Resolved transport binding for a service.
///
/// After the resolver determines where a service lives, it produces
/// a `TransportBinding` that tells the client factory how to connect.
#[derive(Debug, Clone)]
pub enum TransportBinding {
    /// Service is in the same process — use direct dispatch.
    Local,
    /// Service is available at a remote HTTP endpoint.
    Http {
        /// Base URL (e.g., `http://billing-service:8080`).
        base_url: String,
    },
}
