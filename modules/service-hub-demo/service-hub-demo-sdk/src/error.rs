//! Error types for the `PaymentService` contract.

use modkit_canonical_errors_macro::resource_error;

/// Resource error constructors for payment operations.
///
/// Generates typed constructors like `PaymentResourceError::not_found(detail)`.
#[resource_error("gts.cf.demo.service_hub.payment.v1~")]
pub struct PaymentResourceError;
