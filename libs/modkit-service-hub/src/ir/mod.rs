//! Intermediate Representation (IR) for service contracts and transport bindings.

pub mod binding;
pub mod contract;
pub mod validation;

pub use binding::{HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr};
pub use contract::{
    FieldIr, Idempotency, InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef,
};
pub use validation::{ValidationError, validate_contract, validate_http_binding};
