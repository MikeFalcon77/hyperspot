use serde::{Deserialize, Serialize};

/// Intermediate representation of a complete contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractIr {
    /// Contract name, usually the SDK trait name.
    pub name: String,
    /// Module that provides this contract.
    pub module: String,
    /// API version.
    pub version: String,
    /// Methods exposed by this contract.
    pub methods: Vec<MethodIr>,
}

/// Intermediate representation of a single contract method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodIr {
    /// Method name.
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
    /// Request -> Response.
    Unary,
    /// Request -> Stream of responses.
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
    /// A named domain type.
    Named(String),
    /// An optional wrapper.
    Optional(Box<TypeRef>),
    /// A list/vector.
    List(Box<TypeRef>),
    /// A key-value map.
    Map(Box<TypeRef>, Box<TypeRef>),
}

/// Primitive scalar types supported in contracts.
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
    /// Idempotent write — retriable.
    IdempotentWrite,
    /// Non-idempotent write — not retriable without explicit strategy.
    NonIdempotentWrite,
}

pub type ServiceIr = ContractIr;
