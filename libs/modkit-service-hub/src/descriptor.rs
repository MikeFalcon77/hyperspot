//! Static service descriptors for fast runtime lookups.
//!
//! These types mirror the Contract IR but use `&'static` references
//! instead of owned `String`s, enabling zero-allocation resolution
//! at runtime.

use crate::ir::contract::{Idempotency, MethodKind};

/// Compile-time static metadata for a service contract.
///
/// Parallel to [`ServiceIr`](crate::ir::contract::ServiceIr) but uses
/// `&'static` references for zero-allocation lookups during service
/// resolution and dispatch.
pub struct ServiceDescriptor {
    /// Module name (e.g., "billing").
    pub module: &'static str,
    /// Service name (e.g., `PaymentService`).
    pub service: &'static str,
    /// API version (e.g., "v1").
    pub version: &'static str,
    /// Method descriptors for all methods in this service.
    pub methods: &'static [MethodDescriptor],
}

/// Static metadata for a single method within a service.
pub struct MethodDescriptor {
    /// Method name (e.g., "charge").
    pub name: &'static str,
    /// Unary or streaming.
    pub kind: MethodKind,
    /// Idempotency classification for retry decisions.
    pub idempotency: Idempotency,
    /// Input type name (for diagnostics and logging).
    pub input_type: &'static str,
    /// Output type name (for diagnostics and logging).
    pub output_type: &'static str,
}
