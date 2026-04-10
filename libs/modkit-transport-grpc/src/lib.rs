#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
mod backoff;
pub mod client;
pub mod rpc_retry;

#[cfg(windows)]
pub mod windows_named_pipe;

#[cfg(windows)]
pub use windows_named_pipe::{NamedPipeConnection, NamedPipeIncoming, create_named_pipe_incoming};

pub const SECCTX_METADATA_KEY: &str = "x-secctx-bin";

/// Binary gRPC trailer carrying an RFC 9457 problem envelope. The `-bin`
/// suffix is the gRPC convention for binary-valued metadata: tonic handles
/// base64 transport encoding for us.
pub const PROBLEM_METADATA_KEY: &str = "x-modkit-problem-bin";

use modkit_security::{SecurityContext, decode_bin, encode_bin};
use tonic::Status;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};

/// HTTP-style header carrying a bearer token. tonic accepts arbitrary
/// `authorization` metadata; this is the convention used by every project
/// service.
const AUTHORIZATION_HEADER: &str = "authorization";

/// Trait that any in-process security-context-bearing type can implement
/// to expose its bearer token to the gRPC transport layer. The generated
/// gRPC client passes the user's `SecurityContext` through this trait
/// without `modkit-transport-grpc` having to depend on every secret-store
/// crate directly.
pub trait BearerContext {
    /// Returns the bearer token value (without the `Bearer ` prefix), or
    /// `None` when the context is anonymous.
    fn bearer_value(&self) -> Option<String>;
}

impl BearerContext for SecurityContext {
    fn bearer_value(&self) -> Option<String> {
        use secrecy::ExposeSecret as _;
        self.bearer_token().map(|t| t.expose_secret().to_owned())
    }
}

/// Attach `Bearer <token>` to the `authorization` metadata header.
/// Mirrors [`attach_secctx`]'s `Result<(), Status>` convention so all four
/// metadata helpers in this crate (`attach_secctx`, `attach_problem`,
/// `attach_bearer`) have a uniform surface.
///
/// Anonymous contexts (no token) succeed with no header inserted.
///
/// # Errors
/// Returns `Status::internal` if the token contains bytes that cannot be
/// encoded as a tonic metadata value.
pub fn attach_bearer<C: BearerContext>(
    metadata: &mut MetadataMap,
    ctx: &C,
) -> Result<(), Status> {
    let Some(token) = ctx.bearer_value() else {
        return Ok(());
    };
    let value: MetadataValue<_> = format!("Bearer {token}").parse().map_err(
        |e: tonic::metadata::errors::InvalidMetadataValue| {
            Status::internal(format!("bearer token invalid: {e}"))
        },
    )?;
    // `authorization` is hardcoded ASCII-lowercase — `from_static` is
    // infallible at the type level, no spurious error path.
    metadata.insert(MetadataKey::from_static(AUTHORIZATION_HEADER), value);
    Ok(())
}

/// Encode `SecurityContext` into gRPC metadata.
///
/// # Errors
/// Returns `Status::internal` if encoding fails.
pub fn attach_secctx(meta: &mut MetadataMap, ctx: &SecurityContext) -> Result<(), Status> {
    let encoded = encode_bin(ctx).map_err(|e| Status::internal(format!("secctx encode: {e}")))?;

    meta.insert_bin(SECCTX_METADATA_KEY, MetadataValue::from_bytes(&encoded));
    Ok(())
}

/// Decode `SecurityContext` from gRPC metadata.
///
/// # Errors
/// Returns `Status::unauthenticated` if the metadata is missing or decoding fails.
pub fn extract_secctx(meta: &MetadataMap) -> Result<SecurityContext, Status> {
    let raw = meta
        .get_bin(SECCTX_METADATA_KEY)
        .ok_or_else(|| Status::unauthenticated("missing secctx metadata"))?;

    let bytes = raw
        .to_bytes()
        .map_err(|e| Status::unauthenticated(format!("invalid secctx metadata: {e}")))?;

    decode_bin(bytes.as_ref()).map_err(|e| Status::unauthenticated(format!("secctx decode: {e}")))
}

/// Attach a serializable problem envelope (e.g. RFC 9457 `ProblemDetails`)
/// to gRPC trailers under [`PROBLEM_METADATA_KEY`]. Bytes are encoded into
/// the `-bin` trailer slot — base64 over the wire is handled by tonic.
///
/// The function is generic over the envelope type so neither this crate nor
/// `modkit-contract` need to coordinate on a single canonical schema.
///
/// # Errors
/// Returns `Status::internal` when JSON serialization of the envelope fails.
pub fn attach_problem<P: serde::Serialize>(
    meta: &mut MetadataMap,
    problem: &P,
) -> Result<(), Status> {
    let bytes = serde_json::to_vec(problem)
        .map_err(|e| Status::internal(format!("problem encode: {e}")))?;
    meta.insert_bin(PROBLEM_METADATA_KEY, MetadataValue::from_bytes(&bytes));
    Ok(())
}

/// Extract a serializable problem envelope from gRPC trailers. Returns
/// `None` when the trailer is absent or the bytes do not deserialize into
/// `P` — callers fall back to status-code-based mapping in that case.
#[must_use]
pub fn extract_problem<P: serde::de::DeserializeOwned>(meta: &MetadataMap) -> Option<P> {
    let raw = meta.get_bin(PROBLEM_METADATA_KEY)?;
    let bytes = raw.to_bytes().ok()?;
    serde_json::from_slice::<P>(&bytes).ok()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod problem_trailer_tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct DummyProblem {
        title: String,
        detail: String,
        status: u16,
    }

    #[test]
    fn roundtrip_through_binary_trailer() {
        let mut meta = MetadataMap::new();
        let original = DummyProblem {
            title: "Кириллица 🦀".to_owned(),
            detail: "non-ASCII detail with emoji 🚀 and chars: ümlaut".to_owned(),
            status: 500,
        };
        attach_problem(&mut meta, &original).unwrap();
        let got: DummyProblem = extract_problem(&meta).expect("trailer present");
        assert_eq!(got, original);
    }

    #[test]
    fn returns_none_when_absent() {
        let meta = MetadataMap::new();
        assert!(extract_problem::<DummyProblem>(&meta).is_none());
    }

    #[test]
    fn returns_none_on_garbage() {
        let mut meta = MetadataMap::new();
        meta.insert_bin(
            PROBLEM_METADATA_KEY,
            MetadataValue::from_bytes(b"not json at all"),
        );
        assert!(extract_problem::<DummyProblem>(&meta).is_none());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod bearer_tests {
    use super::*;

    /// Inline `BearerContext` impl so the test does not depend on
    /// `modkit-security`'s SecurityContext shape.
    struct StubBearer(Option<&'static str>);
    impl BearerContext for StubBearer {
        fn bearer_value(&self) -> Option<String> {
            self.0.map(|s| s.to_owned())
        }
    }

    #[test]
    fn attach_bearer_writes_authorization_header() {
        let mut md = MetadataMap::new();
        attach_bearer(&mut md, &StubBearer(Some("abc"))).unwrap();
        let v = md.get("authorization").unwrap();
        assert_eq!(v.to_str().unwrap(), "Bearer abc");
    }

    #[test]
    fn attach_bearer_skips_anonymous_context() {
        let mut md = MetadataMap::new();
        attach_bearer(&mut md, &StubBearer(None)).unwrap();
        assert!(md.get("authorization").is_none());
    }
}
