//! Central [`ServiceHub`] — the main entry point for resolving service clients.
//!
//! The hub orchestrates resolution, factory invocation, and caching through
//! the [`ClientHub`](modkit::ClientHub). Callers interact with the hub via
//! `resolve::<dyn MyService>()` and get back an `Arc<dyn MyService>`.

use modkit::ClientHub;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::ServiceHubError;
use crate::factory::ServiceClientFactory;
use crate::resolver::{ResolutionPreference, ResolvedTarget, Resolver};
use crate::transport::TransportBinding;

/// Central hub for resolving typed service clients.
///
/// Combines a [`Resolver`] (decides *where*) with registered
/// [`ServiceClientFactory`] instances (decides *how*) and a
/// [`ClientHub`](modkit::ClientHub) (caches results).
///
/// # Usage
///
/// ```ignore
/// let client: Arc<dyn PaymentService> = hub.resolve::<dyn PaymentService>().await?;
/// client.charge(request).await?;
/// ```
pub struct ServiceHub {
    client_hub: Arc<ClientHub>,
    resolver: Arc<dyn Resolver>,
    default_preference: ResolutionPreference,
    factories: RwLock<HashMap<&'static str, Arc<dyn ServiceClientFactory>>>,
    resolved: RwLock<HashMap<&'static str, bool>>,
}

impl ServiceHub {
    /// Create a new hub backed by the given [`ClientHub`](modkit::ClientHub)
    /// and [`Resolver`].
    #[must_use]
    pub fn new(client_hub: Arc<ClientHub>, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            client_hub,
            resolver,
            default_preference: ResolutionPreference::default(),
            factories: RwLock::new(HashMap::new()),
            resolved: RwLock::new(HashMap::new()),
        }
    }

    /// Set the default [`ResolutionPreference`] for all `resolve` calls.
    #[must_use]
    pub fn with_preference(mut self, pref: ResolutionPreference) -> Self {
        self.default_preference = pref;
        self
    }

    /// Register a [`ServiceClientFactory`] for a service type.
    pub fn register_factory(&self, factory: Arc<dyn ServiceClientFactory>) {
        let key = factory.type_key();
        self.factories.write().insert(key, factory);
    }

    /// Returns a reference to the underlying [`ClientHub`](modkit::ClientHub).
    #[must_use]
    pub fn client_hub(&self) -> &Arc<ClientHub> {
        &self.client_hub
    }

    /// Resolve a service client by trait object type.
    ///
    /// If a client is already cached in the [`ClientHub`](modkit::ClientHub),
    /// it is returned immediately. Otherwise the hub:
    /// 1. Finds the registered factory for `T`.
    /// 2. Calls the [`Resolver`] to determine where the service lives.
    /// 3. Invokes the factory to create and register the client.
    /// 4. Returns the newly registered client from the hub.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceHubError::NoFactory`] if no factory is registered.
    /// Returns [`ServiceHubError::ResolutionFailed`] if the resolver cannot
    /// find the service.
    /// Returns [`ServiceHubError::ClientHub`] if the hub lookup fails after
    /// registration.
    pub async fn resolve<T>(&self) -> Result<Arc<T>, ServiceHubError>
    where
        T: ?Sized + Send + Sync + 'static,
    {
        // Fast path: already in the client hub.
        if let Ok(client) = self.client_hub.get::<T>() {
            return Ok(client);
        }

        let type_key = std::any::type_name::<T>();

        // Find the factory.
        let factory = {
            let factories = self.factories.read();
            factories
                .get(type_key)
                .cloned()
                .ok_or_else(|| ServiceHubError::NoFactory {
                    type_key: type_key.to_owned(),
                })?
        };

        // Check if we already attempted resolution (avoids re-resolving on
        // repeated failures from factory registration).
        {
            let resolved = self.resolved.read();
            if resolved.contains_key(type_key) {
                // Already resolved once — try the hub again (factory should
                // have registered it).
                return self
                    .client_hub
                    .get::<T>()
                    .map_err(|e| ServiceHubError::ClientHub(e.to_string()));
            }
        }

        // Resolve the target.
        let descriptor = factory.descriptor();
        let target = self
            .resolver
            .resolve(descriptor, self.default_preference)
            .await?;

        let binding = match target {
            ResolvedTarget::Local => TransportBinding::Local,
            ResolvedTarget::Http { base_url } => TransportBinding::Http { base_url },
        };

        // Create and register the client.
        factory
            .create_and_register(&binding, &self.client_hub)
            .await?;

        // Mark as resolved.
        self.resolved.write().insert(type_key, true);

        // Return from the hub.
        self.client_hub
            .get::<T>()
            .map_err(|e| ServiceHubError::ClientHub(e.to_string()))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::descriptor::{MethodDescriptor, ServiceDescriptor};
    use crate::ir::contract::{Idempotency, MethodKind};
    use crate::resolver::ResolvedTarget;
    use async_trait::async_trait;

    // -- Test service trait --------------------------------------------------

    #[async_trait]
    trait DemoService: Send + Sync + std::fmt::Debug {
        async fn ping(&self) -> String;
    }

    #[derive(Debug)]
    struct DemoServiceImpl;

    #[async_trait]
    impl DemoService for DemoServiceImpl {
        async fn ping(&self) -> String {
            "pong".to_owned()
        }
    }

    // -- Stub resolver -------------------------------------------------------

    struct StubResolver {
        target: ResolvedTarget,
    }

    #[async_trait]
    impl Resolver for StubResolver {
        async fn resolve(
            &self,
            _descriptor: &ServiceDescriptor,
            _preference: ResolutionPreference,
        ) -> Result<ResolvedTarget, ServiceHubError> {
            Ok(self.target.clone())
        }
    }

    // -- Stub factory --------------------------------------------------------

    static DEMO_DESCRIPTOR: ServiceDescriptor = ServiceDescriptor {
        module: "demo",
        contract: "DemoService",
        service: "DemoService",
        version: "v1",
        methods: &[MethodDescriptor {
            name: "ping",
            kind: MethodKind::Unary,
            idempotency: Idempotency::SafeRead,
            input_type: "()",
            output_type: "String",
        }],
    };

    struct DemoFactory;

    #[async_trait]
    impl ServiceClientFactory for DemoFactory {
        fn type_key(&self) -> &'static str {
            std::any::type_name::<dyn DemoService>()
        }

        fn descriptor(&self) -> &'static ServiceDescriptor {
            &DEMO_DESCRIPTOR
        }

        async fn create_and_register(
            &self,
            _binding: &TransportBinding,
            hub: &Arc<ClientHub>,
        ) -> Result<(), ServiceHubError> {
            let client: Arc<dyn DemoService> = Arc::new(DemoServiceImpl);
            hub.register::<dyn DemoService>(client);
            Ok(())
        }
    }

    // -- Tests ---------------------------------------------------------------

    #[tokio::test]
    async fn resolve_returns_cached() {
        let client_hub = Arc::new(ClientHub::new());
        let resolver = Arc::new(StubResolver {
            target: ResolvedTarget::Local,
        });

        // Pre-register the client directly in the hub.
        let direct: Arc<dyn DemoService> = Arc::new(DemoServiceImpl);
        client_hub.register::<dyn DemoService>(direct);

        let hub = ServiceHub::new(client_hub, resolver);

        let client = hub.resolve::<dyn DemoService>().await.unwrap();
        assert_eq!(client.ping().await, "pong");
    }

    #[tokio::test]
    async fn register_factory_and_resolve() {
        let client_hub = Arc::new(ClientHub::new());
        let resolver = Arc::new(StubResolver {
            target: ResolvedTarget::Local,
        });

        let hub = ServiceHub::new(client_hub, resolver);
        hub.register_factory(Arc::new(DemoFactory));

        let client = hub.resolve::<dyn DemoService>().await.unwrap();
        assert_eq!(client.ping().await, "pong");
    }

    #[tokio::test]
    async fn resolve_no_factory_returns_error() {
        let client_hub = Arc::new(ClientHub::new());
        let resolver = Arc::new(StubResolver {
            target: ResolvedTarget::Local,
        });

        let hub = ServiceHub::new(client_hub, resolver);

        let err = hub.resolve::<dyn DemoService>().await.unwrap_err();
        assert!(matches!(err, ServiceHubError::NoFactory { .. }));
    }
}
