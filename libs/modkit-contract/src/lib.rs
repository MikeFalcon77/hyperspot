#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod contract;
pub mod descriptor;
pub mod error;
pub mod http;
pub mod ir;

pub use contract::{Contract, ServiceContract};
pub use descriptor::{ContractDescriptor, MethodDescriptor, ServiceDescriptor};
pub use error::ContractError;
pub use ir::{
    ContractIr, FieldIr, HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr,
    Idempotency, InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef,
    ValidationError, validate_contract, validate_http_binding,
};
pub use modkit_contract_macros::contract;
