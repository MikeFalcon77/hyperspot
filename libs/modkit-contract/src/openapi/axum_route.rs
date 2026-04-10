//! Axum route helper that publishes the contract's OpenAPI spec at the
//! well-known path `/.well-known/openapi.json`.
//!
//! Industry convention (OpenAPI Initiative + AWS / Kong / Tyk patterns):
//! each service exposes its own spec; gateways aggregate. Consumers fetch
//! from this exact path.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::Value;

/// Build an [`axum::Router`] that serves `spec` at
/// `/.well-known/openapi.json`. The spec is shared via [`Arc`] so each
/// request only clones the smart pointer, not the JSON document.
///
/// # Example
///
/// ```ignore
/// use modkit_contract::openapi::{generate_openapi_spec, well_known_openapi_route};
///
/// let spec = generate_openapi_spec(&contract_ir, &binding, &schemas);
/// let app = well_known_openapi_route(spec).merge(my_routes);
/// ```
#[must_use]
pub fn well_known_openapi_route(spec: Value) -> Router {
    let shared: Arc<Value> = Arc::new(spec);
    Router::new().route("/.well-known/openapi.json", get(move || serve(shared.clone())))
}

async fn serve(spec: Arc<Value>) -> impl IntoResponse {
    Json((*spec).clone())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::json;
    use tower::util::ServiceExt as _;

    #[tokio::test]
    async fn serves_spec_at_well_known_path() {
        let spec = json!({
            "openapi": "3.1.0",
            "info": { "title": "X", "version": "v1" },
            "paths": {},
        });
        let app = well_known_openapi_route(spec.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body, spec);
    }

    #[tokio::test]
    async fn other_paths_404() {
        let app = well_known_openapi_route(json!({}));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/other")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
}
