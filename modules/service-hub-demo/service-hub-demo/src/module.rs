//! Module definition and wiring for service-hub-demo.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use modkit::context::ModuleCtx;
use modkit::contracts::Module;
use modkit_service_hub::hub::ServiceHub;
use modkit_service_hub::ir::validation::{validate_contract, validate_http_binding};
use modkit_service_hub::policy::{PolicyStack, TracingPolicy};
use modkit_service_hub::resolver::HybridResolver;
use service_hub_demo_sdk::contract::{PaymentService, payment_service_ir};

use crate::binding::payment_service_http_binding;
use crate::client::factory::PaymentServiceFactory;
use crate::client::local::PaymentLocalClient;
use crate::config::ServiceHubDemoConfig;
use crate::domain::service::PaymentDomainService;

/// Service hub demo module — provides `PaymentService`.
pub struct ServiceHubDemoModule {
    service: OnceLock<Arc<PaymentDomainService>>,
}

impl ServiceHubDemoModule {
    /// Create a new uninitialized module.
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: OnceLock::new(),
        }
    }
}

impl Default for ServiceHubDemoModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Module for ServiceHubDemoModule {
    async fn init(&self, ctx: &ModuleCtx) -> anyhow::Result<()> {
        // 1. Validate IR at startup (fail-fast).
        let contract_ir = payment_service_ir();
        let http_binding = payment_service_http_binding();
        validate_contract(&contract_ir)
            .map_err(|errs| anyhow::anyhow!("Contract IR validation failed: {errs:?}"))?;
        validate_http_binding(&contract_ir, &http_binding)
            .map_err(|errs| anyhow::anyhow!("HTTP binding IR validation failed: {errs:?}"))?;

        // 2. Create domain service.
        let domain_svc = Arc::new(PaymentDomainService::new());
        self.service
            .set(domain_svc.clone())
            .map_err(|_| anyhow::anyhow!("service-hub-demo already initialized"))?;

        // 3. Build policy stack.
        let mut policy_stack = PolicyStack::new();
        policy_stack.push(Arc::new(TracingPolicy));
        let policy_stack = Arc::new(policy_stack);

        // 4. Build resolver (local + static config).
        let config: ServiceHubDemoConfig = ctx.config_or_default()?;
        let resolver = Arc::new(HybridResolver::new(config.remote_endpoints));
        resolver.register_local("service-hub-demo");

        // 5. Create ServiceHub wrapping ClientHub.
        let service_hub = Arc::new(ServiceHub::new(ctx.client_hub(), resolver));

        // 6. Register factory.
        service_hub.register_factory(Arc::new(PaymentServiceFactory {
            local_service: Some(domain_svc.clone()),
            policy_stack: Arc::clone(&policy_stack),
        }));

        // 7. Register ServiceHub in ClientHub for consumers.
        ctx.client_hub().register::<ServiceHub>(service_hub);

        // 8. Direct-register local client for in-process consumers.
        let local_client: Arc<dyn PaymentService> =
            Arc::new(PaymentLocalClient::new(domain_svc, policy_stack));
        ctx.client_hub()
            .register::<dyn PaymentService>(local_client);

        tracing::info!("service-hub-demo initialized");
        Ok(())
    }
}
