//! Service resolution — determines where a service is located at runtime.
//!
//! The [`Resolver`] trait abstracts the resolution strategy. The default
//! [`HybridResolver`] checks local registrations, then the
//! [`DirectoryClient`](modkit::DirectoryClient), then static configuration.

use async_trait::async_trait;
use modkit::DirectoryClient;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::descriptor::ServiceDescriptor;
use crate::error::ServiceHubError;

/// Where a service should be dispatched to after resolution.
#[derive(Debug, Clone)]
pub enum ResolvedTarget {
    /// Service is in the same process — use direct dispatch.
    Local,
    /// Service is at a remote HTTP endpoint.
    Http {
        /// Base URL (e.g., `http://billing-service:8080`).
        base_url: String,
    },
}

/// Preference hint for the resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResolutionPreference {
    /// Prefer a local implementation if available, fall back to remote.
    #[default]
    PreferLocal,
    /// Prefer a remote implementation, fall back to local.
    PreferRemote,
    /// Only accept a local implementation; fail if unavailable.
    LocalOnly,
    /// Only accept a remote implementation; fail if unavailable.
    RemoteOnly,
}

/// Resolves a [`ServiceDescriptor`] to a [`ResolvedTarget`].
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve the given service descriptor to a transport target.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceHubError::ResolutionFailed`] if the service cannot
    /// be resolved under the given preference.
    async fn resolve(
        &self,
        descriptor: &ServiceDescriptor,
        preference: ResolutionPreference,
    ) -> Result<ResolvedTarget, ServiceHubError>;
}

/// Multi-strategy resolver: local registry, then directory, then static config.
///
/// Resolution order depends on [`ResolutionPreference`]:
/// - `PreferLocal` / `LocalOnly` — check local set first.
/// - `PreferRemote` / `RemoteOnly` — check directory / static config first.
///
/// Fallback chain (for `PreferLocal`):
/// 1. Local module set (`register_local`)
/// 2. [`DirectoryClient::resolve_rest_service`](modkit::DirectoryClient::resolve_rest_service)
/// 3. Static endpoint map
pub struct HybridResolver {
    local_modules: RwLock<HashSet<String>>,
    directory: Option<Arc<dyn DirectoryClient>>,
    static_endpoints: HashMap<String, String>,
}

impl HybridResolver {
    /// Create a new resolver with optional static endpoint overrides.
    ///
    /// Static endpoints map module names to base URLs (e.g.,
    /// `"billing" -> "http://billing:8080"`).
    #[must_use]
    pub fn new(static_endpoints: HashMap<String, String>) -> Self {
        Self {
            local_modules: RwLock::new(HashSet::new()),
            directory: None,
            static_endpoints,
        }
    }

    /// Attach a [`DirectoryClient`](modkit::DirectoryClient) for dynamic
    /// service discovery.
    #[must_use]
    pub fn with_directory(mut self, dir: Arc<dyn DirectoryClient>) -> Self {
        self.directory = Some(dir);
        self
    }

    /// Register a module as locally available (in-process).
    pub fn register_local(&self, module_name: &str) {
        self.local_modules.write().insert(module_name.to_owned());
    }

    /// Check if a module is registered locally.
    fn is_local(&self, module: &str) -> bool {
        self.local_modules.read().contains(module)
    }

    /// Try to resolve via the directory client.
    async fn resolve_via_directory(&self, module: &str) -> Option<String> {
        let dir = self.directory.as_ref()?;
        let endpoint = dir.resolve_rest_service(module).await.ok()?;
        Some(endpoint.uri)
    }

    /// Try to resolve via static endpoint configuration.
    fn resolve_via_static(&self, module: &str) -> Option<String> {
        self.static_endpoints.get(module).cloned()
    }

    /// Resolve to a remote target (directory first, then static config).
    async fn resolve_remote(&self, module: &str) -> Option<ResolvedTarget> {
        if let Some(url) = self.resolve_via_directory(module).await {
            return Some(ResolvedTarget::Http { base_url: url });
        }
        self.resolve_via_static(module)
            .map(|url| ResolvedTarget::Http { base_url: url })
    }
}

#[async_trait]
impl Resolver for HybridResolver {
    async fn resolve(
        &self,
        descriptor: &ServiceDescriptor,
        preference: ResolutionPreference,
    ) -> Result<ResolvedTarget, ServiceHubError> {
        let module = descriptor.module;

        match preference {
            ResolutionPreference::PreferLocal => {
                if self.is_local(module) {
                    return Ok(ResolvedTarget::Local);
                }
                if let Some(target) = self.resolve_remote(module).await {
                    return Ok(target);
                }
                Err(ServiceHubError::ResolutionFailed {
                    service: descriptor.service.to_owned(),
                    reason: format!("module '{module}' not found locally or remotely"),
                })
            }
            ResolutionPreference::PreferRemote => {
                if let Some(target) = self.resolve_remote(module).await {
                    return Ok(target);
                }
                if self.is_local(module) {
                    return Ok(ResolvedTarget::Local);
                }
                Err(ServiceHubError::ResolutionFailed {
                    service: descriptor.service.to_owned(),
                    reason: format!("module '{module}' not found remotely or locally"),
                })
            }
            ResolutionPreference::LocalOnly => {
                if self.is_local(module) {
                    Ok(ResolvedTarget::Local)
                } else {
                    Err(ServiceHubError::ResolutionFailed {
                        service: descriptor.service.to_owned(),
                        reason: format!("module '{module}' not registered locally"),
                    })
                }
            }
            ResolutionPreference::RemoteOnly => {
                if let Some(target) = self.resolve_remote(module).await {
                    Ok(target)
                } else {
                    Err(ServiceHubError::ResolutionFailed {
                        service: descriptor.service.to_owned(),
                        reason: format!(
                            "module '{module}' not found via directory or static config"
                        ),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ir::contract::{Idempotency, MethodKind};

    static TEST_DESCRIPTOR: ServiceDescriptor = ServiceDescriptor {
        module: "billing",
        contract: "PaymentService",
        service: "PaymentService",
        version: "v1",
        methods: &[crate::descriptor::MethodDescriptor {
            name: "charge",
            kind: MethodKind::Unary,
            idempotency: Idempotency::NonIdempotentWrite,
            input_type: "ChargeRequest",
            output_type: "ChargeResponse",
        }],
    };

    #[tokio::test]
    async fn simple_resolver_local_found() {
        let resolver = HybridResolver::new(HashMap::new());
        resolver.register_local("billing");

        let target = resolver
            .resolve(&TEST_DESCRIPTOR, ResolutionPreference::PreferLocal)
            .await
            .unwrap();
        assert!(matches!(target, ResolvedTarget::Local));
    }

    #[tokio::test]
    async fn simple_resolver_static_found() {
        let mut endpoints = HashMap::new();
        endpoints.insert("billing".to_owned(), "http://billing:8080".to_owned());
        let resolver = HybridResolver::new(endpoints);

        let target = resolver
            .resolve(&TEST_DESCRIPTOR, ResolutionPreference::PreferLocal)
            .await
            .unwrap();
        match target {
            ResolvedTarget::Http { base_url } => {
                assert_eq!(base_url, "http://billing:8080");
            }
            ResolvedTarget::Local => panic!("expected Http target"),
        }
    }

    #[tokio::test]
    async fn simple_resolver_prefer_local_fallback() {
        let mut endpoints = HashMap::new();
        endpoints.insert("billing".to_owned(), "http://billing:8080".to_owned());
        // Do NOT register "billing" locally — should fall back to static.
        let resolver = HybridResolver::new(endpoints);

        let target = resolver
            .resolve(&TEST_DESCRIPTOR, ResolutionPreference::PreferLocal)
            .await
            .unwrap();
        assert!(matches!(target, ResolvedTarget::Http { .. }));
    }

    #[tokio::test]
    async fn simple_resolver_local_only_fails() {
        let resolver = HybridResolver::new(HashMap::new());

        let err = resolver
            .resolve(&TEST_DESCRIPTOR, ResolutionPreference::LocalOnly)
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceHubError::ResolutionFailed { .. }));
    }

    #[tokio::test]
    async fn simple_resolver_remote_only_static() {
        let mut endpoints = HashMap::new();
        endpoints.insert("billing".to_owned(), "http://billing:9090".to_owned());
        let resolver = HybridResolver::new(endpoints);

        let target = resolver
            .resolve(&TEST_DESCRIPTOR, ResolutionPreference::RemoteOnly)
            .await
            .unwrap();
        match target {
            ResolvedTarget::Http { base_url } => {
                assert_eq!(base_url, "http://billing:9090");
            }
            ResolvedTarget::Local => panic!("expected Http target"),
        }
    }
}
