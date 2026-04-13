//! Internal data structures for the `#[service_contract]` macro.
//!
//! These models are populated by the parser and consumed by the code generator.

/// Parsed representation of an entire `#[service_contract]` trait.
pub struct ServiceContractModel {
    /// Module name from the `module = "..."` attribute parameter.
    pub module: String,
    /// API version from the `version = "..."` attribute parameter.
    pub version: String,
    /// The trait name identifier.
    pub trait_name: syn::Ident,
    /// Visibility of the trait.
    pub vis: syn::Visibility,
    /// Supertraits (e.g., `Send + Sync`).
    pub supertraits: syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    /// Parsed methods within the trait.
    pub methods: Vec<MethodModel>,
    /// Preserved attributes (doc comments, cfg, etc.).
    pub attrs: Vec<syn::Attribute>,
}

/// Parsed representation of a single method within the service contract.
pub struct MethodModel {
    /// Method name identifier.
    pub name: syn::Ident,
    /// Whether this method is unary or server-streaming.
    pub kind: MethodKind,
    /// Idempotency classification for retry decisions.
    pub idempotency: Idempotency,
    /// Parameters excluding `&self`.
    pub params: Vec<ParamModel>,
    /// The `T` from `Result<T, E>` in the return type.
    pub output_type: syn::Type,
    /// The `E` from `Result<T, E>` in the return type.
    pub error_type: syn::Type,
    /// Preserved attributes (doc comments, cfg, etc.).
    pub attrs: Vec<syn::Attribute>,
    /// Original method signature (for trait generation).
    pub sig: syn::Signature,
}

/// A single parameter in a method signature (excluding `&self`).
pub struct ParamModel {
    /// Parameter name.
    pub name: syn::Ident,
    /// Parameter type.
    pub ty: syn::Type,
}

/// Whether a method is unary or server-streaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    /// Request -> Response (async fn).
    Unary,
    /// Request -> Stream of responses.
    ServerStreaming,
}

/// Idempotency classification for retry policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotency {
    /// Safe read operation -- always retriable.
    SafeRead,
    /// Idempotent write -- retriable (PUT-like semantics).
    IdempotentWrite,
    /// Non-idempotent write -- NOT retriable without explicit strategy.
    NonIdempotentWrite,
}
