//! Factory for creating `PaymentService` clients based on transport binding.

use std::sync::Arc;

use async_trait::async_trait;
use modkit::ClientHub;
use modkit_service_hub::descriptor::ServiceDescriptor;
use modkit_service_hub::error::ServiceHubError;
use modkit_service_hub::factory::ServiceClientFactory;
use modkit_service_hub::policy::PolicyStack;
use modkit_service_hub::transport::TransportBinding;
use service_hub_demo_sdk::contract::{PAYMENT_SERVICE_DESCRIPTOR, PaymentService};

use modkit_http::HttpClient;

use crate::binding::payment_service_http_binding;
use crate::client::local::PaymentLocalClient;
use crate::client::remote::PaymentHttpClient;
use crate::domain::service::PaymentDomainService;

/// Factory that creates `PaymentService` clients for local or HTTP transport.
pub struct PaymentServiceFactory {
    /// Local domain service (if module is in-process).
    pub local_service: Option<Arc<PaymentDomainService>>,
    /// Policy stack applied to each call.
    pub policy_stack: Arc<PolicyStack>,
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
                    Arc::new(PaymentLocalClient::new(Arc::clone(svc), Arc::clone(&self.policy_stack)));
                hub.register::<dyn PaymentService>(client);
                Ok(())
            }
            TransportBinding::Http { base_url } => {
                let http = HttpClient::builder()
                    .build()
                    .map_err(|e| ServiceHubError::Transport(Box::new(e)))?;
                let client: Arc<dyn PaymentService> = Arc::new(PaymentHttpClient::new(
                    http,
                    base_url.clone(),
                    Arc::new(payment_service_http_binding()),
                ));
                hub.register::<dyn PaymentService>(client);
                Ok(())
            }
        }
    }
}
