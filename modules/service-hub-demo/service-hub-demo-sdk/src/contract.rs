//! `PaymentService` contract definition and Contract IR.
//!
//! The Rust trait is the source of truth. The `#[service_contract]` macro
//! derives the Contract IR, static descriptor, and `ServiceContract` impl.

use std::pin::Pin;

use futures_core::Stream;
use modkit_canonical_errors::CanonicalError;
use modkit_security::SecurityContext;
use modkit_service_hub::service_contract;

use crate::models::{ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter, PaymentSummary};

/// Boxed stream type returned by streaming `PaymentService` methods.
pub type PaymentStream<T> = Pin<Box<dyn Stream<Item = Result<T, CanonicalError>> + Send + 'static>>;

/// Payment service contract -- the same trait for local and remote consumption.
///
/// All parameter types are owned and `'static`-compatible.
/// Registered in `ClientHub` as `Arc<dyn PaymentService>`.
#[service_contract(module = "service-hub-demo", version = "v1")]
pub trait PaymentService: Send + Sync {
    /// Charge a payment. Non-idempotent write.
    ///
    /// # Errors
    ///
    /// Returns a `CanonicalError` if the charge fails (e.g., invalid amount,
    /// payment processor error).
    #[idempotency(NonIdempotentWrite)]
    async fn charge(
        &self,
        ctx: SecurityContext,
        req: ChargeRequest,
    ) -> Result<ChargeResponse, CanonicalError>;

    /// Get an invoice by ID. Safe read.
    ///
    /// # Errors
    ///
    /// Returns a `CanonicalError` if the invoice is not found or access is
    /// denied.
    #[idempotency(SafeRead)]
    async fn get_invoice(
        &self,
        ctx: SecurityContext,
        invoice_id: String,
    ) -> Result<Invoice, CanonicalError>;

    /// List payments as a server-streaming response.
    #[idempotency(SafeRead)]
    #[streaming]
    fn list_payments(
        &self,
        ctx: SecurityContext,
        filter: ListPaymentsFilter,
    ) -> Result<PaymentSummary, CanonicalError>;
}
