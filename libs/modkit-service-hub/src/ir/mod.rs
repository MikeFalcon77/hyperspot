pub use modkit_contract::ir::{
    ContractIr, FieldIr, HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr,
    Idempotency, InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef,
    ValidationError, validate_contract, validate_http_binding,
};

pub mod binding {
    pub use modkit_contract::ir::binding::{
        HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr,
    };
}

pub mod contract {
    pub use modkit_contract::ir::contract::{
        ContractIr, FieldIr, Idempotency, InputShape, MethodIr, MethodKind, PrimitiveType,
        ServiceIr, TypeRef,
    };
}

pub mod validation {
    pub use modkit_contract::ir::validation::{
        ValidationError, validate_contract, validate_http_binding,
    };
}
