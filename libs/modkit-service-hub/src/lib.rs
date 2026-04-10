//! Service contract hub framework for `ModKit`.
//!
//! Provides the IR pipeline, service resolution, transport abstraction,
//! and policy stack for unified local/remote service invocation.

pub mod error;
pub mod ir;

pub use error::ServiceHubError;
pub use ir::{
    FieldIr, HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr, Idempotency,
    InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef, ValidationError,
    validate_contract, validate_http_binding,
};
