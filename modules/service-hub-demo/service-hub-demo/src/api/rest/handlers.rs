//! Axum REST handlers for `PaymentService` (proof-of-concept, no `OperationBuilder`).

use std::convert::Infallible;
use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query};
use axum::response::sse::{Event, Sse};
use futures_util::stream::{self, StreamExt as _};
use http::HeaderMap;
use modkit_canonical_errors::{CanonicalError, Problem};
use modkit_security::SecurityContext;
use service_hub_demo_sdk::models::{ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter};

use crate::domain::service::PaymentDomainService;

// ---------------------------------------------------------------------------
// charge
// ---------------------------------------------------------------------------

/// `POST /api/service-hub-demo/v1/payments/charge`
///
/// # Errors
///
/// Returns an HTTP error tuple when the domain service rejects the charge.
pub async fn charge_handler(
    headers: HeaderMap,
    Extension(svc): Extension<Arc<PaymentDomainService>>,
    axum::Json(req): axum::Json<ChargeRequest>,
) -> Result<axum::Json<ChargeResponse>, (http::StatusCode, axum::Json<serde_json::Value>)> {
    let ctx = extract_security_context(&headers);
    match svc.charge(&ctx, &req) {
        Ok(resp) => Ok(axum::Json(resp)),
        Err(e) => Err(error_to_response(&e)),
    }
}

// ---------------------------------------------------------------------------
// get_invoice
// ---------------------------------------------------------------------------

/// `GET /api/service-hub-demo/v1/invoices/{invoice_id}`
///
/// # Errors
///
/// Returns an HTTP error tuple when the invoice is not found or access is denied.
pub async fn get_invoice_handler(
    headers: HeaderMap,
    Extension(svc): Extension<Arc<PaymentDomainService>>,
    Path(invoice_id): Path<String>,
) -> Result<axum::Json<Invoice>, (http::StatusCode, axum::Json<serde_json::Value>)> {
    let ctx = extract_security_context(&headers);
    match svc.get_invoice(&ctx, &invoice_id) {
        Ok(invoice) => Ok(axum::Json(invoice)),
        Err(e) => Err(error_to_response(&e)),
    }
}

// ---------------------------------------------------------------------------
// list_payments (SSE)
// ---------------------------------------------------------------------------

/// `GET /api/service-hub-demo/v1/payments`
pub async fn list_payments_handler(
    headers: HeaderMap,
    Extension(svc): Extension<Arc<PaymentDomainService>>,
    Query(filter): Query<ListPaymentsFilter>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let ctx = extract_security_context(&headers);
    let item_stream = svc.list_payments(&ctx, &filter);

    let event_stream = item_stream
        .map(|item| match item {
            Ok(summary) => {
                let data = serde_json::to_string(&summary).unwrap_or_default();
                Ok(Event::default().data(data))
            }
            Err(e) => {
                let problem: Problem = e.into();
                let data = serde_json::to_string(&problem).unwrap_or_default();
                Ok(Event::default().event("error").data(data))
            }
        })
        .chain(stream::once(async { Ok(Event::default().event("done")) }));

    Sse::new(event_stream)
}

// ---------------------------------------------------------------------------
// SecurityContext extraction
// ---------------------------------------------------------------------------

/// Extract `SecurityContext` from HTTP headers.
///
/// Looks for `Authorization: Bearer <token>` and builds a context with the token.
/// Falls back to anonymous if no auth header is present.
fn extract_security_context(headers: &HeaderMap) -> SecurityContext {
    if let Some(auth) = headers.get(http::header::AUTHORIZATION)
        && let Ok(value) = auth.to_str()
            && let Some(token) = value.strip_prefix("Bearer ")
                && let Ok(ctx) = SecurityContext::builder()
                    .bearer_token(token.to_owned())
                    .build()
                {
                    return ctx;
                }
    SecurityContext::anonymous()
}

// ---------------------------------------------------------------------------
// error helper
// ---------------------------------------------------------------------------

/// Map a `CanonicalError` to an Axum-compatible error tuple.
fn error_to_response(err: &CanonicalError) -> (http::StatusCode, axum::Json<serde_json::Value>) {
    let status_code = err.status_code();
    let problem = Problem::from_error(err).unwrap_or_else(|_| Problem {
        problem_type: String::new(),
        title: "Internal".to_owned(),
        status: 500,
        detail: "serialization error".to_owned(),
        instance: None,
        trace_id: None,
        context: serde_json::Value::Null,
    });
    let http_status =
        http::StatusCode::from_u16(status_code).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_value(&problem).unwrap_or_default();
    (http_status, axum::Json(body))
}
