//! Conversion from [`TransportError`] into [`modkit_canonical_errors::CanonicalError`].
//!
//! Lives in `modkit-contract` (not in `modkit-canonical-errors`) so the
//! canonical-errors crate stays a leaf in the workspace dep graph: it does
//! not need to know about transport-layer error envelopes. Gated behind the
//! `canonical-errors` feature.
//!
//! # Mapping policy
//!
//! Per [`docs/arch/errors/DESIGN.md`] §3.4, resource-scoped canonical errors
//! (`NotFound`, `AlreadyExists`, `PermissionDenied`, ...) carry a
//! `resource_type` GTS URI and a `resource_name`. A generic transport-layer
//! failure does **not** know which resource the peer was operating on — it
//! only sees a status code (HTTP or gRPC) and an opaque message. We therefore
//! intentionally LOSE the canonical category for resource-scoped failures and
//! collapse them onto [`CanonicalError::internal`] with the original status
//! preserved in `detail`.
//!
//! Callers that need to react to specific failure modes (e.g. retry on 503,
//! treat 404 as cache miss) **must** match on [`TransportError`] *before*
//! converting to [`CanonicalError`]. Once converted, only the three
//! non-resource categories survive intact:
//! - `Internal` ← network/timeout/serialization/url/Internal/Unknown/DataLoss
//! - `ServiceUnavailable` ← Unavailable / 503
//! - `Unauthenticated` ← Unauthenticated / 401
//!
//! Future work (per `cpt-cf-errors-interface-problem-roundtrip` in PRD §3.3):
//! when a `Problem` envelope is present in the response, decode its
//! `problem_type` GTS URI back into the typed variant *with* its resource
//! info. That requires a `TryFrom<Problem> for CanonicalError` in
//! canonical-errors which is currently future work.

use modkit_canonical_errors::CanonicalError;

use crate::runtime::transport_error::TransportError;

impl From<TransportError> for CanonicalError {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::Problem(problem) => problem_to_canonical(problem),
            TransportError::HttpStatus { status, body } => http_status_to_canonical(status, &body),
            #[cfg(feature = "grpc-client")]
            TransportError::Grpc { code, message } => grpc_code_to_canonical(code, message),
            TransportError::Network(_msg) => CanonicalError::service_unavailable().create(),
            TransportError::Timeout(d) => CanonicalError::internal(format!("timeout after {d:?}"))
                .create(),
            TransportError::Serialization(msg) => {
                CanonicalError::internal(format!("serialization error: {msg}")).create()
            }
            TransportError::Sse(msg) => {
                CanonicalError::internal(format!("SSE protocol error: {msg}")).create()
            }
            TransportError::UrlBuild(msg) => {
                CanonicalError::internal(format!("URL build error: {msg}")).create()
            }
        }
    }
}

fn problem_to_canonical(problem: modkit_canonical_errors::Problem) -> CanonicalError {
    // Without `TryFrom<Problem>` we cannot reconstruct resource info from the
    // wire. Fall back to HTTP-status mapping, preserving the title+detail.
    http_status_to_canonical(
        problem.status,
        &format!("{}: {}", problem.title, problem.detail),
    )
}

fn http_status_to_canonical(status: u16, body: &str) -> CanonicalError {
    let preview: &str = if body.len() > 200 { &body[..200] } else { body };
    match status {
        401 => CanonicalError::unauthenticated()
            .with_reason(preview.to_owned())
            .create(),
        503 => CanonicalError::service_unavailable().create(),
        s => CanonicalError::internal(format!("HTTP {s}: {preview}")).create(),
    }
}

#[cfg(feature = "grpc-client")]
fn grpc_code_to_canonical(code: tonic::Code, message: String) -> CanonicalError {
    use tonic::Code;
    match code {
        Code::Unauthenticated => CanonicalError::unauthenticated()
            .with_reason(message)
            .create(),
        Code::Unavailable => CanonicalError::service_unavailable().create(),
        // All other gRPC codes (NotFound/AlreadyExists/PermissionDenied/...)
        // are resource-scoped categories; without the original Problem body
        // we don't know which resource was at fault, so we collapse to
        // `internal` with the category preserved in the detail string.
        // Callers that need fine-grained handling must match on
        // `TransportError::Grpc { code, .. }` before this conversion.
        other => CanonicalError::internal(format!("gRPC {other:?}: {message}")).create(),
    }
}
