//! Factory trait for creating service clients from transport bindings.
//!
//! Each service contract has a corresponding factory that knows how to
//! construct either a local or HTTP client and register it in the
//! [`ClientHub`](modkit::ClientHub).

use async_trait::async_trait;
use modkit::ClientHub;
use std::sync::Arc;

use crate::descriptor::ServiceDescriptor;
use crate::error::ServiceHubError;
use crate::transport::TransportBinding;

/// Creates and registers typed service clients.
///
/// One factory exists per service contract type. It knows how to build
/// a local pass-through client or an HTTP-backed client and register the
/// result in the [`ClientHub`](modkit::ClientHub).
#[async_trait]
pub trait ServiceClientFactory: Send + Sync {
    /// Type key used for [`ClientHub`](modkit::ClientHub) registration.
    ///
    /// Typically `std::any::type_name::<dyn MyService>()`.
    fn type_key(&self) -> &'static str;

    /// The [`ServiceDescriptor`] this factory creates clients for.
    fn descriptor(&self) -> &'static ServiceDescriptor;

    /// Build a client for the given binding and register it in the hub.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceHubError::Transport`] if the client cannot be
    /// created (e.g., invalid URL, TLS failure).
    async fn create_and_register(
        &self,
        binding: &TransportBinding,
        hub: &Arc<ClientHub>,
    ) -> Result<(), ServiceHubError>;
}
