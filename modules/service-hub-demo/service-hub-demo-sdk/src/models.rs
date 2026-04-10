//! Domain models for the `PaymentService` contract.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to charge a payment.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChargeRequest {
    /// Amount in smallest currency unit (e.g., cents).
    pub amount_cents: i64,
    /// ISO 4217 currency code (e.g., "USD").
    pub currency: String,
    /// Human-readable description.
    pub description: String,
}

/// Response from a successful charge.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChargeResponse {
    /// Unique payment identifier.
    pub payment_id: Uuid,
    /// Current status of the payment.
    pub status: PaymentStatus,
}

/// Current status of a payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    /// Payment is pending processing.
    Pending,
    /// Payment completed successfully.
    Completed,
    /// Payment failed.
    Failed,
}

/// A payment invoice.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[allow(
    clippy::struct_field_names,
    reason = "invoice_id is the canonical domain identifier"
)]
pub struct Invoice {
    /// Unique invoice identifier.
    pub invoice_id: Uuid,
    /// Associated payment identifier.
    pub payment_id: Uuid,
    /// Amount in smallest currency unit.
    pub amount_cents: i64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Invoice description.
    pub description: String,
    /// Current payment status.
    pub status: PaymentStatus,
}

/// Summary of a payment for streaming list responses.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PaymentSummary {
    /// Unique payment identifier.
    pub payment_id: Uuid,
    /// Amount in smallest currency unit.
    pub amount_cents: i64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Current payment status.
    pub status: PaymentStatus,
}

/// Filter criteria for listing payments.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ListPaymentsFilter {
    /// Filter by payment status.
    pub status: Option<PaymentStatus>,
    /// Filter by currency code.
    pub currency: Option<String>,
}
