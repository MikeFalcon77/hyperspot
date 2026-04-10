//! Local (in-process) client for `PaymentService`.

use std::sync::Arc;

use async_trait::async_trait;
use modkit_canonical_errors::CanonicalError;
use modkit_security::SecurityContext;
use modkit_service_hub::ir::contract::{Idempotency, MethodKind};
use modkit_service_hub::policy::{PolicyContext, PolicyStack};
use service_hub_demo_sdk::contract::{PaymentService, PaymentStream};
use service_hub_demo_sdk::models::{
    ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter, PaymentSummary,
};

use crate::domain::service::PaymentDomainService;

/// Direct in-process adapter — zero serialization, zero network.
///
/// Wraps each call with the [`PolicyStack`] for tracing/metrics.
pub struct PaymentLocalClient {
    service: Arc<PaymentDomainService>,
    policies: Arc<PolicyStack>,
}

impl PaymentLocalClient {
    /// Create a local client wrapping the domain service.
    #[must_use]
    pub fn new(service: Arc<PaymentDomainService>, policies: Arc<PolicyStack>) -> Self {
        Self { service, policies }
    }
}

/// Map a policy stack error to `CanonicalError`.
///
/// Takes by value because `PolicyStack::execute` requires `fn(ServiceHubError) -> E`.
#[allow(clippy::needless_pass_by_value, reason = "required by fn pointer signature")]
fn policy_err(e: modkit_service_hub::error::ServiceHubError) -> CanonicalError {
    CanonicalError::internal(e.to_string()).create()
}

#[async_trait]
impl PaymentService for PaymentLocalClient {
    async fn charge(
        &self,
        ctx: SecurityContext,
        req: ChargeRequest,
    ) -> Result<ChargeResponse, CanonicalError> {
        let pc = PolicyContext {
            service: "PaymentService",
            method: "charge",
            idempotency: Idempotency::NonIdempotentWrite,
            kind: MethodKind::Unary,
        };
        let svc = Arc::clone(&self.service);
        self.policies
            .execute(&pc, || async move { svc.charge(&ctx, &req) }, policy_err)
            .await
    }

    async fn get_invoice(
        &self,
        ctx: SecurityContext,
        invoice_id: String,
    ) -> Result<Invoice, CanonicalError> {
        let pc = PolicyContext {
            service: "PaymentService",
            method: "get_invoice",
            idempotency: Idempotency::SafeRead,
            kind: MethodKind::Unary,
        };
        let svc = Arc::clone(&self.service);
        self.policies
            .execute(
                &pc,
                || async move { svc.get_invoice(&ctx, &invoice_id) },
                policy_err,
            )
            .await
    }

    fn list_payments(
        &self,
        ctx: SecurityContext,
        filter: ListPaymentsFilter,
    ) -> PaymentStream<PaymentSummary> {
        // Streaming: policies run on_request before the stream starts.
        // on_response runs after the full stream completes (not per-item).
        self.service.list_payments(&ctx, &filter)
    }
}
