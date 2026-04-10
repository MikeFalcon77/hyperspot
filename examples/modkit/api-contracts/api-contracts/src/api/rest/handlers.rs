//! Axum REST handlers for `PaymentService` (proof-of-concept, no `OperationBuilder`).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::extract::{Path, Query};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream::{self, StreamExt as _};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use modkit_canonical_errors::{CanonicalError, Problem};
use modkit_security::SecurityContext;
use api_contracts_sdk::models::{ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter};

use crate::domain::service::PaymentDomainService;

/// RFC 9457 problem envelope wrapped in an axum response. Sets
/// `Content-Type: application/problem+json` per spec — generic clients can
/// rely on the media type to route the body through their problem-aware
/// parser instead of treating it as plain JSON.
pub struct ProblemResponse(StatusCode, Problem);

impl IntoResponse for ProblemResponse {
    fn into_response(self) -> Response {
        let ProblemResponse(status, problem) = self;
        let body = serde_json::to_vec(&problem)
            .expect("Problem is serde-derived; serialization is infallible for our schema");
        let mut response = Response::new(axum::body::Body::from(body));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

/// Bearer-token validation outcome for the request.
enum AuthOutcome {
    Anonymous,
    Authenticated(SecurityContext),
    /// A `Bearer` token was present but couldn't be turned into a valid
    /// `SecurityContext`. Caller must reject the request — silently
    /// downgrading to anonymous masks credential bugs in production.
    Invalid,
}

// ---------------------------------------------------------------------------
// charge
// ---------------------------------------------------------------------------

/// `POST /api/api-contracts/v1/payments/charge`
///
/// # Errors
///
/// Returns a `ProblemResponse` when the bearer token is malformed or the
/// domain service rejects the charge.
pub async fn charge_handler(
    headers: HeaderMap,
    Extension(svc): Extension<Arc<PaymentDomainService>>,
    axum::Json(req): axum::Json<ChargeRequest>,
) -> Result<axum::Json<ChargeResponse>, ProblemResponse> {
    let ctx = require_security_context(&headers)?;
    match svc.charge(&ctx, &req) {
        Ok(resp) => Ok(axum::Json(resp)),
        Err(e) => Err(error_to_response(&e)),
    }
}

// ---------------------------------------------------------------------------
// get_invoice
// ---------------------------------------------------------------------------

/// `GET /api/api-contracts/v1/invoices/{invoice_id}`
///
/// # Errors
///
/// Returns a `ProblemResponse` when the bearer token is malformed, the
/// invoice is not found, or access is denied.
pub async fn get_invoice_handler(
    headers: HeaderMap,
    Extension(svc): Extension<Arc<PaymentDomainService>>,
    Path(invoice_id): Path<String>,
) -> Result<axum::Json<Invoice>, ProblemResponse> {
    let ctx = require_security_context(&headers)?;
    match svc.get_invoice(&ctx, &invoice_id) {
        Ok(invoice) => Ok(axum::Json(invoice)),
        Err(e) => Err(error_to_response(&e)),
    }
}

// ---------------------------------------------------------------------------
// list_payments (SSE)
// ---------------------------------------------------------------------------

/// `GET /api/api-contracts/v1/payments`
///
/// On bearer-token validation failure returns a `ProblemResponse` (so the
/// client sees `application/problem+json` instead of an SSE stream).
/// Otherwise emits an SSE stream of `PaymentSummary` items terminated by
/// `event: done`.
pub async fn list_payments_handler(
    headers: HeaderMap,
    Extension(svc): Extension<Arc<PaymentDomainService>>,
    Query(filter): Query<ListPaymentsFilter>,
) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>, ProblemResponse> {
    let ctx = require_security_context(&headers)?;
    let item_stream = svc.list_payments(&ctx, &filter);

    let event_stream = item_stream
        .map(|item| {
            Ok(match item {
                Ok(summary) => {
                    let data = serde_json::to_string(&summary)
                        .expect("PaymentSummary is serde-derived; infallible for our schema");
                    Event::default().data(data)
                }
                Err(e) => {
                    let problem: Problem = e.into();
                    let data = serde_json::to_string(&problem)
                        .expect("Problem is serde-derived; infallible for our schema");
                    Event::default().event("error").data(data)
                }
            })
        })
        .chain(stream::once(async { Ok(Event::default().event("done")) }));

    // Heartbeat keeps the connection alive through NAT/proxy idle timeouts
    // (typical 30-60s). 15s is a safe value for browsers + most proxies.
    Ok(Sse::new(event_stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

// ---------------------------------------------------------------------------
// SecurityContext extraction
// ---------------------------------------------------------------------------

/// Validate the inbound `Authorization: Bearer ...` header (if any) into
/// either an anonymous, authenticated, or invalid outcome. Malformed
/// bearer tokens must NOT silently degrade to anonymous — that hides
/// credential bugs in production callers.
fn classify_auth(headers: &HeaderMap) -> AuthOutcome {
    let Some(auth_header) = headers.get(header::AUTHORIZATION) else {
        return AuthOutcome::Anonymous;
    };
    let Ok(value) = auth_header.to_str() else {
        return AuthOutcome::Invalid;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        // Header is present but not in the `Bearer <token>` shape — invalid.
        return AuthOutcome::Invalid;
    };
    match SecurityContext::builder()
        .bearer_token(token.to_owned())
        .build()
    {
        Ok(ctx) => AuthOutcome::Authenticated(ctx),
        Err(_) => AuthOutcome::Invalid,
    }
}

/// Produce a [`SecurityContext`] for the handler, rejecting the request
/// with `401 Unauthenticated` (canonical Problem envelope) when a bearer
/// token is present but malformed.
fn require_security_context(headers: &HeaderMap) -> Result<SecurityContext, ProblemResponse> {
    match classify_auth(headers) {
        AuthOutcome::Anonymous => Ok(SecurityContext::anonymous()),
        AuthOutcome::Authenticated(ctx) => Ok(ctx),
        AuthOutcome::Invalid => {
            let err = CanonicalError::unauthenticated()
                .with_reason("malformed Authorization header")
                .create();
            Err(error_to_response(&err))
        }
    }
}

// ---------------------------------------------------------------------------
// error helper
// ---------------------------------------------------------------------------

/// Map a [`CanonicalError`] to a [`ProblemResponse`]. The HTTP status comes
/// from the canonical category's published mapping; the body is the full
/// RFC 9457 envelope (with GTS URI in `type`, plus `context`).
fn error_to_response(err: &CanonicalError) -> ProblemResponse {
    let status_code = err.status_code();
    let problem = Problem::from_error(err)
        .expect("Problem::from_error is infallible for first-party CanonicalError variants");
    let http_status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    ProblemResponse(http_status, problem)
}
