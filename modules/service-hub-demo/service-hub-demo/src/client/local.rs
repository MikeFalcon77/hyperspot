//! Local (in-process) client for `PaymentService`.

use std::sync::Arc;

use async_trait::async_trait;
use modkit_canonical_errors::CanonicalError;
use modkit_security::SecurityContext;
use service_hub_demo_sdk::contract::{PaymentService, PaymentStream};
use service_hub_demo_sdk::models::{
    ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter, PaymentSummary,
};

use crate::domain::service::PaymentDomainService;

/// Direct in-process adapter — zero serialization, zero network.
pub struct PaymentLocalClient {
    service: Arc<PaymentDomainService>,
}

impl PaymentLocalClient {
    /// Create a local client wrapping the domain service.
    #[must_use]
    pub fn new(service: Arc<PaymentDomainService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl PaymentService for PaymentLocalClient {
    async fn charge(
        &self,
        ctx: SecurityContext,
        req: ChargeRequest,
    ) -> Result<ChargeResponse, CanonicalError> {
        self.service.charge(&ctx, &req)
    }

    async fn get_invoice(
        &self,
        ctx: SecurityContext,
        invoice_id: String,
    ) -> Result<Invoice, CanonicalError> {
        self.service.get_invoice(&ctx, &invoice_id)
    }

    fn list_payments(
        &self,
        ctx: SecurityContext,
        filter: ListPaymentsFilter,
    ) -> PaymentStream<PaymentSummary> {
        self.service.list_payments(&ctx, &filter)
    }
}
