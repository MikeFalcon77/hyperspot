#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod contract;
pub mod descriptor;
pub mod error;
pub mod grpc_repr;
pub mod http;
pub mod ir;
pub mod policy;
pub mod runtime;

#[cfg(feature = "openapi")]
pub mod openapi;

#[cfg(feature = "grpc-client")]
pub mod grpc;

pub use contract::{Contract, ServiceContract};
pub use descriptor::{ContractDescriptor, ContractKind, MethodDescriptor, ServiceDescriptor};
pub use error::ContractError;
pub use grpc_repr::{GrpcRepr, GrpcReprScalar, SecurityContextMarker, assert_security_context};
pub use ir::{
    ContractIr, FieldIr, GrpcBindingIr, GrpcIdempotency, GrpcMethodBindingIr, HttpBindingIr,
    HttpFieldBinding, HttpMethod, HttpMethodBindingIr, Idempotency, InputShape, MethodIr,
    MethodKind, PrimitiveType, ServiceIr, TypeRef, ValidationError, validate_contract,
    validate_grpc_binding, validate_http_binding,
};
pub use modkit_contract_macros::{
    ContractError, ProtoBridge, contract, grpc_contract, rest_contract,
};
pub use policy::{Policy, PolicyContext, PolicyStack, TracingPolicy};

// Wire envelope: re-export `Problem` from the canonical-errors leaf so all
// downstream crates have a single import path to the RFC 9457 envelope.
#[cfg(feature = "canonical-errors")]
pub use modkit_canonical_errors::{Problem, ProblemCategory};
