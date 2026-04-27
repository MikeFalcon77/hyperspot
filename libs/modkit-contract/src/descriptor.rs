use crate::ir::contract::{Idempotency, MethodKind};

/// Compile-time static metadata for a contract.
pub struct ContractDescriptor {
    /// Module name.
    pub module: &'static str,
    /// Contract name, usually the SDK trait name.
    pub contract: &'static str,
    /// Compatibility service name for old service-hub call sites.
    pub service: &'static str,
    /// API version.
    pub version: &'static str,
    /// Method descriptors for all methods in this contract.
    pub methods: &'static [MethodDescriptor],
}

impl ContractDescriptor {
    /// Compatibility accessor for old service-oriented call sites.
    #[must_use]
    pub const fn service(&self) -> &'static str {
        self.service
    }
}

/// Static metadata for a single method within a contract.
pub struct MethodDescriptor {
    /// Method name.
    pub name: &'static str,
    /// Unary or streaming.
    pub kind: MethodKind,
    /// Idempotency classification for retry decisions.
    pub idempotency: Idempotency,
    /// Input type name for diagnostics and logging.
    pub input_type: &'static str,
    /// Output type name for diagnostics and logging.
    pub output_type: &'static str,
}

pub type ServiceDescriptor = ContractDescriptor;
