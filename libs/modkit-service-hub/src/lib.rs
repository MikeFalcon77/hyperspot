//! Service contract hub framework for `ModKit`.
//!
//! Provides the IR pipeline, service resolution, transport abstraction,
//! and policy stack for unified local/remote service invocation.

pub mod contract_trait;
pub mod descriptor;
pub mod error;
pub mod factory;
pub mod http;
pub mod hub;
pub mod ir;
pub mod policy;
pub mod resolver;
pub mod transport;

pub use contract_trait::ServiceContract;
pub use descriptor::{MethodDescriptor, ServiceDescriptor};
pub use error::ServiceHubError;
pub use factory::ServiceClientFactory;
pub use hub::ServiceHub;
pub use ir::{
    FieldIr, HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr, Idempotency,
    InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef, ValidationError,
    validate_contract, validate_http_binding,
};
pub use policy::{Policy, PolicyContext, PolicyStack, TracingPolicy};
pub use resolver::{HybridResolver, ResolutionPreference, ResolvedTarget, Resolver};
pub use transport::TransportBinding;
