//! HTTP (remote) client for `PaymentService`.
//!
//! Uses [`modkit_http::HttpClient`] and the binding IR to make REST calls
//! to a remote `PaymentService` instance.

use std::sync::Arc;

use async_trait::async_trait;
use modkit_canonical_errors::CanonicalError;
use modkit_http::HttpClient;
use modkit_security::SecurityContext;
use modkit_service_hub::http::dispatch::build_url;
use modkit_service_hub::ir::binding::HttpBindingIr;
use secrecy::ExposeSecret;
use service_hub_demo_sdk::contract::{PaymentService, PaymentStream};
use service_hub_demo_sdk::models::{
    ChargeRequest, ChargeResponse, Invoice, ListPaymentsFilter, PaymentSummary,
};

/// HTTP client that calls a remote `PaymentService` over REST.
pub struct PaymentHttpClient {
    http: HttpClient,
    base_url: String,
    binding: Arc<HttpBindingIr>,
}

impl PaymentHttpClient {
    /// Create a new HTTP client.
    #[must_use]
    pub fn new(http: HttpClient, base_url: String, binding: Arc<HttpBindingIr>) -> Self {
        Self {
            http,
            base_url,
            binding,
        }
    }

    /// Look up a method binding by name, returning a `CanonicalError` on failure.
    fn find_method(
        &self,
        name: &str,
    ) -> Result<&modkit_service_hub::ir::binding::HttpMethodBindingIr, CanonicalError> {
        self.binding.find_method(name).ok_or_else(|| {
            CanonicalError::internal(format!("missing HTTP binding for method '{name}'")).create()
        })
    }

    /// Map a non-success HTTP response to a `CanonicalError`.
    ///
    /// Tries to parse the body as RFC 9457 Problem JSON first, falling back
    /// to a generic internal error with the status and a body preview.
    fn map_http_error(status: http::StatusCode, body: &str) -> CanonicalError {
        // Try to parse the body as a Problem JSON and extract a meaningful error.
        if let Ok(problem) = serde_json::from_str::<modkit_canonical_errors::Problem>(body) {
            return status_to_canonical(problem.status, &problem.detail);
        }
        // Fallback: generic internal error with status + body excerpt.
        let preview = if body.len() > 200 { &body[..200] } else { body };
        CanonicalError::internal(format!("HTTP {status}: {preview}")).create()
    }
}

/// Map a numeric HTTP status to an appropriate `CanonicalError` variant.
fn status_to_canonical(status: u16, detail: &str) -> CanonicalError {
    use service_hub_demo_sdk::error::PaymentResourceError;

    match status {
        404 => PaymentResourceError::not_found(detail)
            .with_resource("unknown")
            .create(),
        401 => CanonicalError::unauthenticated()
            .with_reason(detail)
            .create(),
        // For all other statuses, use a generic internal error that preserves
        // the detail string. A production client would map more categories.
        _ => CanonicalError::internal(format!("HTTP {status}: {detail}")).create(),
    }
}

/// Attach `Authorization: Bearer <token>` header if the security context carries a token.
fn auth_header(ctx: &SecurityContext) -> Option<String> {
    ctx.bearer_token()
        .map(|t| format!("Bearer {}", t.expose_secret()))
}

/// Helper to convert any error into `CanonicalError::Internal`.
fn internal(msg: &str, err: impl std::fmt::Display) -> CanonicalError {
    CanonicalError::internal(format!("{msg}: {err}")).create()
}

#[async_trait]
impl PaymentService for PaymentHttpClient {
    async fn charge(
        &self,
        ctx: SecurityContext,
        req: ChargeRequest,
    ) -> Result<ChargeResponse, CanonicalError> {
        let method_binding = self.find_method("charge")?;
        let url = build_url(
            &self.base_url,
            &self.binding.base_path,
            method_binding,
            &serde_json::json!({}),
        )
        .map_err(|e| internal("failed to build URL for charge", e))?;

        let mut request = self.http.post(&url);
        if let Some(auth) = auth_header(&ctx) {
            request = request.header("authorization", &auth);
        }
        let resp = request
            .json(&req)
            .map_err(|e| internal("failed to serialize charge request", e))?
            .send()
            .await
            .map_err(|e| internal("HTTP transport error during charge", e))?;

        let status = resp.status();
        if status.is_success() {
            resp.json::<ChargeResponse>()
                .await
                .map_err(|e| internal("failed to parse charge response", e))
        } else {
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body = String::from_utf8_lossy(&body_bytes);
            Err(Self::map_http_error(status, &body))
        }
    }

    async fn get_invoice(
        &self,
        ctx: SecurityContext,
        invoice_id: String,
    ) -> Result<Invoice, CanonicalError> {
        let method_binding = self.find_method("get_invoice")?;
        let url = build_url(
            &self.base_url,
            &self.binding.base_path,
            method_binding,
            &serde_json::json!({ "invoice_id": invoice_id }),
        )
        .map_err(|e| internal("failed to build URL for get_invoice", e))?;

        let mut request = self.http.get(&url);
        if let Some(auth) = auth_header(&ctx) {
            request = request.header("authorization", &auth);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| internal("HTTP transport error during get_invoice", e))?;

        let status = resp.status();
        if status.is_success() {
            resp.json::<Invoice>()
                .await
                .map_err(|e| internal("failed to parse invoice response", e))
        } else {
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body = String::from_utf8_lossy(&body_bytes);
            Err(Self::map_http_error(status, &body))
        }
    }

    fn list_payments(
        &self,
        ctx: SecurityContext,
        filter: ListPaymentsFilter,
    ) -> PaymentStream<PaymentSummary> {
        let http = self.http.clone();
        let base_url = self.base_url.clone();
        let binding = Arc::clone(&self.binding);
        let auth = auth_header(&ctx);

        Box::pin(async_stream::try_stream! {
            let method_binding = binding.find_method("list_payments").ok_or_else(|| {
                CanonicalError::internal(
                    "missing HTTP binding for method 'list_payments'"
                ).create()
            })?;

            // Build fields JSON — absent/null fields are skipped as optional query params.
            let mut fields = serde_json::Map::new();
            if let Some(ref status) = filter.status
                && let Ok(v) = serde_json::to_value(status) {
                    fields.insert("status".to_owned(), v);
                }
            if let Some(ref currency) = filter.currency {
                fields.insert(
                    "currency".to_owned(),
                    serde_json::Value::String(currency.clone()),
                );
            }

            let url = build_url(
                &base_url,
                &binding.base_path,
                method_binding,
                &serde_json::Value::Object(fields),
            )
            .map_err(|e| internal("failed to build URL for list_payments", e))?;

            let mut request = http.get(&url);
            if let Some(ref auth) = auth {
                request = request.header("authorization", auth);
            }
            let resp = request
                .send()
                .await
                .map_err(|e| internal("HTTP transport error during list_payments", e))?;

            // Read the full response body. For success (2xx) `text()` returns
            // the body text. For error status it returns `HttpError::HttpStatus`
            // whose `body_preview` we can use for error mapping.
            let status = resp.status();
            let body = if status.is_success() {
                resp.text().await.map_err(|e| {
                    internal("failed to read list_payments response body", e)
                })?
            } else {
                let body_bytes = resp.bytes().await.unwrap_or_default();
                let body_text = String::from_utf8_lossy(&body_bytes);
                Err(PaymentHttpClient::map_http_error(status, &body_text))?
            };

            for line in body.lines() {
                let line = line.trim();
                if let Some(json_str) = line.strip_prefix("data: ") {
                    let summary: PaymentSummary = serde_json::from_str(json_str)
                        .map_err(|e| internal("failed to parse SSE data line", e))?;
                    yield summary;
                }
                // Skip "event: done", "event: error", empty lines, etc.
            }
        })
    }
}
