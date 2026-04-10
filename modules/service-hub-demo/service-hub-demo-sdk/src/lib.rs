//! SDK for the service-hub-demo module.
//!
//! Provides the `PaymentService` trait contract, domain models, and error types.
//! This crate is transport-agnostic -- no HTTP paths, no gRPC definitions.

pub mod contract;
pub mod error;
pub mod models;

pub use contract::{PaymentService, PaymentStream};
pub use error::PaymentResourceError;
