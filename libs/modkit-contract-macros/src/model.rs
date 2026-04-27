pub struct ContractModel {
    pub module: String,
    pub version: String,
    pub trait_name: syn::Ident,
    pub vis: syn::Visibility,
    pub supertraits: syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    pub methods: Vec<MethodModel>,
    pub attrs: Vec<syn::Attribute>,
}

pub struct MethodModel {
    pub name: syn::Ident,
    pub kind: MethodKind,
    pub idempotency: Idempotency,
    pub params: Vec<ParamModel>,
    pub output_type: syn::Type,
    pub error_type: syn::Type,
    pub attrs: Vec<syn::Attribute>,
    pub sig: syn::Signature,
}

pub struct ParamModel {
    pub name: syn::Ident,
    pub ty: syn::Type,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    Unary,
    ServerStreaming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotency {
    SafeRead,
    IdempotentWrite,
    NonIdempotentWrite,
}
