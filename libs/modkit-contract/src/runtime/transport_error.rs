//! `TransportError` — uniform transport-layer error surfaced by generated
//! REST clients.
//!
//! The wire envelope is `modkit_canonical_errors::Problem` (RFC 9457) when
//! the peer participates in the canonical error system. Older peers may
//! return raw HTTP status codes without a Problem body — those land in
//! [`TransportError::HttpStatus`].

#[cfg(feature = "canonical-errors")]
use modkit_canonical_errors::Problem;

/// Errors produced by the generated REST client transport layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The server returned a structured RFC 9457 `Problem` payload.
    #[cfg(feature = "canonical-errors")]
    #[error("server returned problem: {} ({})", .0.title, .0.status)]
    Problem(Problem),

    /// The server returned a non-success status with a non-Problem body.
    #[error("HTTP {status}: {body}")]
    HttpStatus {
        /// Numeric HTTP status code.
        status: u16,
        /// Body excerpt suitable for diagnostics. Truncated at the call site.
        body: String,
    },

    /// The gRPC server returned a non-OK status. Preserves the original
    /// `tonic::Code` so callers can map it back to canonical categories
    /// without losing information through an HTTP-status detour.
    #[cfg(feature = "grpc-client")]
    #[error("gRPC {code:?}: {message}")]
    Grpc {
        /// The raw gRPC status code as returned by the server.
        code: tonic::Code,
        /// Human-readable detail copied from `tonic::Status::message`.
        message: String,
    },

    /// Low-level network failure (DNS, connect, TLS, mid-flight reset).
    #[error("network error: {0}")]
    Network(String),

    /// The total deadline elapsed before the response was complete.
    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    /// Request or response (de)serialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Server-Sent Events stream error (frame parse, malformed event, etc.).
    #[error("SSE protocol error: {0}")]
    Sse(String),

    /// URL construction error (missing path parameter, invalid template).
    #[error("URL build error: {0}")]
    UrlBuild(String),
}

impl TransportError {
    /// Convenience constructor for [`TransportError::Network`] from a displayable error.
    pub fn network<E: std::fmt::Display>(err: E) -> Self {
        Self::Network(err.to_string())
    }

    /// Convenience constructor for [`TransportError::Serialization`] from a displayable error.
    pub fn serialization<E: std::fmt::Display>(err: E) -> Self {
        Self::Serialization(err.to_string())
    }

    /// Convenience constructor for [`TransportError::Sse`] from a displayable error.
    pub fn sse<E: std::fmt::Display>(err: E) -> Self {
        Self::Sse(err.to_string())
    }

    /// Whether this error class is generally safe to retry without a higher-level
    /// idempotency strategy. Used by [`crate::runtime::retry`] when a method is
    /// declared `#[retryable]`.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            TransportError::Network(_) | TransportError::Timeout(_) | TransportError::Sse(_) => {
                true
            }
            TransportError::HttpStatus { status, .. } => is_retryable_status(*status),
            #[cfg(feature = "canonical-errors")]
            TransportError::Problem(p) => is_retryable_status(p.status),
            #[cfg(feature = "grpc-client")]
            TransportError::Grpc { code, .. } => matches!(
                code,
                tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::Cancelled
                    | tonic::Code::Aborted
                    | tonic::Code::ResourceExhausted
            ),
            TransportError::Serialization(_) | TransportError::UrlBuild(_) => false,
        }
    }
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn network_and_timeout_are_transient() {
        assert!(TransportError::Network("dns".into()).is_transient());
        assert!(TransportError::Timeout(std::time::Duration::from_secs(1)).is_transient());
    }

    #[test]
    fn serialization_is_not_transient() {
        assert!(!TransportError::Serialization("bad json".into()).is_transient());
        assert!(!TransportError::UrlBuild("missing path param".into()).is_transient());
    }

    #[cfg(feature = "grpc-client")]
    #[test]
    fn grpc_transient_codes() {
        for code in [
            tonic::Code::Unavailable,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Cancelled,
            tonic::Code::Aborted,
            tonic::Code::ResourceExhausted,
        ] {
            assert!(
                TransportError::Grpc {
                    code,
                    message: String::new(),
                }
                .is_transient(),
                "expected {code:?} to be transient"
            );
        }
        for code in [
            tonic::Code::NotFound,
            tonic::Code::InvalidArgument,
            tonic::Code::PermissionDenied,
            tonic::Code::Internal,
        ] {
            assert!(
                !TransportError::Grpc {
                    code,
                    message: String::new(),
                }
                .is_transient(),
                "expected {code:?} not to be transient"
            );
        }
    }

    #[test]
    fn five_xx_is_transient_but_4xx_mostly_is_not() {
        assert!(
            TransportError::HttpStatus {
                status: 503,
                body: String::new(),
            }
            .is_transient()
        );
        assert!(
            !TransportError::HttpStatus {
                status: 404,
                body: String::new(),
            }
            .is_transient()
        );
        assert!(
            TransportError::HttpStatus {
                status: 429,
                body: String::new(),
            }
            .is_transient()
        );
    }
}
