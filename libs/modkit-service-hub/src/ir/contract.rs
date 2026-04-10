//! Contract IR — normalized intermediate representation of a service contract.
//!
//! This is the logical description of a service: methods, types, errors.
//! It contains no transport-specific information (no HTTP paths, no gRPC method names).
//! The Rust trait is the source of truth; Contract IR is derived from it.

use serde::{Deserialize, Serialize};

/// Intermediate representation of a complete service contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIr {
    /// Service name (e.g., `PaymentService`).
    pub name: String,
    /// Module that provides this service (e.g., "service-hub-demo").
    pub module: String,
    /// API version (e.g., "v1").
    pub version: String,
    /// Methods exposed by this service.
    pub methods: Vec<MethodIr>,
}

/// Intermediate representation of a single service method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodIr {
    /// Method name (e.g., "charge").
    pub name: String,
    /// Whether this method is unary or streaming.
    pub kind: MethodKind,
    /// Input parameters.
    pub input: InputShape,
    /// Output type reference.
    pub output: TypeRef,
    /// Error type reference, if the method is fallible.
    pub error: Option<TypeRef>,
    /// Idempotency classification for retry decisions.
    pub idempotency: Idempotency,
}

/// Whether a method returns a single value or a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    /// Request -> Response (async fn).
    Unary,
    /// Request -> Stream of responses (fn -> Stream).
    ServerStreaming,
}

/// Shape of a method's input parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputShape {
    /// Ordered list of input fields.
    pub fields: Vec<FieldIr>,
}

/// A single field in an input shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldIr {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: TypeRef,
    /// Whether this field is optional.
    pub optional: bool,
}

/// Reference to a type used in method signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TypeRef {
    /// A primitive scalar type.
    Primitive(PrimitiveType),
    /// A named domain type (e.g., `ChargeRequest`).
    Named(String),
    /// An optional wrapper.
    Optional(Box<TypeRef>),
    /// A list/vector.
    List(Box<TypeRef>),
    /// A key-value map.
    Map(Box<TypeRef>, Box<TypeRef>),
}

/// Primitive scalar types supported in service contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveType {
    /// UTF-8 string.
    String,
    /// 32-bit signed integer.
    I32,
    /// 64-bit signed integer.
    I64,
    /// 64-bit unsigned integer.
    U64,
    /// 64-bit floating point.
    F64,
    /// Boolean.
    Bool,
    /// UUID.
    Uuid,
    /// Raw bytes.
    Bytes,
}

/// Idempotency classification for retry policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Idempotency {
    /// Safe read operation — always retriable.
    SafeRead,
    /// Idempotent write — retriable (PUT-like semantics).
    IdempotentWrite,
    /// Non-idempotent write — NOT retriable without explicit strategy.
    NonIdempotentWrite,
}
