//! Local client adapter for `PaymentService`.
//!
//! The HTTP client is produced by `#[modkit::rest_contract]` in the SDK crate;
//! only the in-process `PaymentLocalClient` adapter remains here.

pub mod local;
