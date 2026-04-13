//! Factory for creating `PaymentService` clients based on transport binding.

use std::sync::Arc;

use async_trait::async_trait;
use modkit::ClientHub;
use modkit_service_hub::descriptor::ServiceDescriptor;
use modkit_service_hub::error::ServiceHubError;
use modkit_service_hub::factory::ServiceClientFactory;
use modkit_service_hub::transport::TransportBinding;
use service_hub_demo_sdk::contract::{PaymentService, PAYMENT_SERVICE_DESCRIPTOR};

use crate::client::local::PaymentLocalClient;
use crate::domain::service::PaymentDomainService;

/// Factory that creates `PaymentService` clients for local or HTTP transport.
pub struct PaymentServiceFactory {
    /// Local domain service (if module is in-process).
    pub local_service: Option<Arc<PaymentDomainService>>,
}

#[async_trait]
impl ServiceClientFactory for PaymentServiceFactory {
    fn type_key(&self) -> &'static str {
        std::any::type_name::<dyn PaymentService>()
    }

    fn descriptor(&self) -> &'static ServiceDescriptor {
        &PAYMENT_SERVICE_DESCRIPTOR
    }

    async fn create_and_register(
        &self,
        binding: &TransportBinding,
        hub: &Arc<ClientHub>,
    ) -> Result<(), ServiceHubError> {
        match binding {
            TransportBinding::Local => {
                let svc = self.local_service.as_ref().ok_or_else(|| {
                    ServiceHubError::ResolutionFailed {
                        service: "PaymentService".to_owned(),
                        reason: "local service not available".to_owned(),
                    }
                })?;
                let client: Arc<dyn PaymentService> =
                    Arc::new(PaymentLocalClient::new(Arc::clone(svc)));
                hub.register::<dyn PaymentService>(client);
                Ok(())
            }
            TransportBinding::Http { .. } => Err(ServiceHubError::Transport(
                "HTTP transport not yet implemented (Phase F)".into(),
            )),
        }
    }
}
