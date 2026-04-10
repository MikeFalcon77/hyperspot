//! Marker trait connecting a Rust trait to its service descriptor and IR.
//!
//! Implemented for `dyn PaymentService`, etc. In the proof-of-concept this is manual;
//! a future `#[service_contract]` macro will generate it automatically.

use crate::descriptor::ServiceDescriptor;
use crate::ir::contract::ServiceIr;

/// Connects a `dyn Trait` type to its [`ServiceDescriptor`] and
/// [`ServiceIr`](crate::ir::contract::ServiceIr).
///
/// This trait is the bridge between the Rust type system and the
/// service hub's runtime metadata. Implement it for your service
/// trait object (e.g., `dyn PaymentService`) so the hub can look up
/// descriptors and build IR on demand.
pub trait ServiceContract: Send + Sync + 'static {
    /// Returns the static descriptor for fast runtime lookups.
    fn descriptor() -> &'static ServiceDescriptor;

    /// Builds the full Contract IR (allocates).
    ///
    /// Used for validation and codegen — not on the hot path.
    fn contract_ir() -> ServiceIr;
}
