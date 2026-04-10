//! Route registration for `PaymentService` REST endpoints.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::{Extension, Router};

use crate::domain::service::PaymentDomainService;

use super::handlers;

/// Register all `PaymentService` REST routes on the given router.
pub fn register_routes(router: Router, service: Arc<PaymentDomainService>) -> Router {
    router
        .route(
            "/api/service-hub-demo/v1/payments/charge",
            post(handlers::charge_handler),
        )
        .route(
            "/api/service-hub-demo/v1/invoices/{invoice_id}",
            get(handlers::get_invoice_handler),
        )
        .route(
            "/api/service-hub-demo/v1/payments",
            get(handlers::list_payments_handler),
        )
        .layer(Extension(service))
}
