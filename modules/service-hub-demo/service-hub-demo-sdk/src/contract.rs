//! `PaymentService` contract definition and Contract IR.
//!
//! The Rust trait is the source of truth. The Contract IR is derived from it
//! and used by validators and runtime helpers.

use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use modkit_canonical_errors::CanonicalError;
use modkit_security::SecurityContext;

use modkit_service_hub::descriptor::{MethodDescriptor, ServiceDescriptor};
use modkit_service_hub::ir::contract::{
    FieldIr, Idempotency, InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef,
};

use crate::models::{ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter, PaymentSummary};

/// Boxed stream type returned by streaming `PaymentService` methods.
pub type PaymentStream<T> = Pin<Box<dyn Stream<Item = Result<T, CanonicalError>> + Send + 'static>>;

/// Payment service contract -- the same trait for local and remote consumption.
///
/// All parameter types are owned and `'static`-compatible.
/// Registered in `ClientHub` as `Arc<dyn PaymentService>`.
#[async_trait]
pub trait PaymentService: Send + Sync {
    /// Charge a payment. Non-idempotent write.
    ///
    /// # Errors
    ///
    /// Returns a `CanonicalError` if the charge fails (e.g., invalid amount,
    /// payment processor error).
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
    async fn get_invoice(
        &self,
        ctx: SecurityContext,
        invoice_id: String,
    ) -> Result<Invoice, CanonicalError>;

    /// List payments as a server-streaming response.
    fn list_payments(
        &self,
        ctx: SecurityContext,
        filter: ListPaymentsFilter,
    ) -> PaymentStream<PaymentSummary>;
}

/// Static descriptor for `PaymentService` — zero-allocation runtime metadata.
pub static PAYMENT_SERVICE_DESCRIPTOR: ServiceDescriptor = ServiceDescriptor {
    module: "service-hub-demo",
    service: "PaymentService",
    version: "v1",
    methods: &[
        MethodDescriptor {
            name: "charge",
            kind: MethodKind::Unary,
            idempotency: Idempotency::NonIdempotentWrite,
            input_type: "ChargeRequest",
            output_type: "ChargeResponse",
        },
        MethodDescriptor {
            name: "get_invoice",
            kind: MethodKind::Unary,
            idempotency: Idempotency::SafeRead,
            input_type: "String",
            output_type: "Invoice",
        },
        MethodDescriptor {
            name: "list_payments",
            kind: MethodKind::ServerStreaming,
            idempotency: Idempotency::SafeRead,
            input_type: "ListPaymentsFilter",
            output_type: "PaymentSummary",
        },
    ],
};

/// Build the Contract IR for `PaymentService`.
///
/// This is the normalized description of the service, derived from the trait above.
/// Used for validation, runtime helpers, and future codegen.
#[must_use]
pub fn payment_service_ir() -> ServiceIr {
    ServiceIr {
        name: "PaymentService".to_owned(),
        module: "service-hub-demo".to_owned(),
        version: "v1".to_owned(),
        methods: vec![
            MethodIr {
                name: "charge".to_owned(),
                kind: MethodKind::Unary,
                input: InputShape {
                    fields: vec![
                        FieldIr {
                            name: "ctx".to_owned(),
                            ty: TypeRef::Named("SecurityContext".to_owned()),
                            optional: false,
                        },
                        FieldIr {
                            name: "req".to_owned(),
                            ty: TypeRef::Named("ChargeRequest".to_owned()),
                            optional: false,
                        },
                    ],
                },
                output: TypeRef::Named("ChargeResponse".to_owned()),
                error: Some(TypeRef::Named("CanonicalError".to_owned())),
                idempotency: Idempotency::NonIdempotentWrite,
            },
            MethodIr {
                name: "get_invoice".to_owned(),
                kind: MethodKind::Unary,
                input: InputShape {
                    fields: vec![
                        FieldIr {
                            name: "ctx".to_owned(),
                            ty: TypeRef::Named("SecurityContext".to_owned()),
                            optional: false,
                        },
                        FieldIr {
                            name: "invoice_id".to_owned(),
                            ty: TypeRef::Primitive(PrimitiveType::String),
                            optional: false,
                        },
                    ],
                },
                output: TypeRef::Named("Invoice".to_owned()),
                error: Some(TypeRef::Named("CanonicalError".to_owned())),
                idempotency: Idempotency::SafeRead,
            },
            MethodIr {
                name: "list_payments".to_owned(),
                kind: MethodKind::ServerStreaming,
                input: InputShape {
                    fields: vec![
                        FieldIr {
                            name: "ctx".to_owned(),
                            ty: TypeRef::Named("SecurityContext".to_owned()),
                            optional: false,
                        },
                        FieldIr {
                            name: "filter".to_owned(),
                            ty: TypeRef::Named("ListPaymentsFilter".to_owned()),
                            optional: false,
                        },
                    ],
                },
                output: TypeRef::Named("PaymentSummary".to_owned()),
                error: Some(TypeRef::Named("CanonicalError".to_owned())),
                idempotency: Idempotency::SafeRead,
            },
        ],
    }
}
