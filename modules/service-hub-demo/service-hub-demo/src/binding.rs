//! HTTP binding IR for `PaymentService` (provider-side).
//!
//! This lives in the module crate, NOT the SDK, because transport
//! bindings are a provider concern.

use modkit_contract::ir::binding::{HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr};

/// Build the HTTP binding projection for `PaymentService`.
#[must_use]
pub fn payment_service_http_binding() -> HttpBindingIr {
    HttpBindingIr {
        base_path: "/api/service-hub-demo/v1".to_owned(),
        methods: vec![
            HttpMethodBindingIr {
                method_name: "charge".to_owned(),
                http_method: HttpMethod::Post,
                path_template: "/payments/charge".to_owned(),
                field_bindings: vec![HttpFieldBinding::Body],
            },
            HttpMethodBindingIr {
                method_name: "get_invoice".to_owned(),
                http_method: HttpMethod::Get,
                path_template: "/invoices/{invoice_id}".to_owned(),
                field_bindings: vec![HttpFieldBinding::Path {
                    field: "invoice_id".to_owned(),
                    param: "invoice_id".to_owned(),
                }],
            },
            HttpMethodBindingIr {
                method_name: "list_payments".to_owned(),
                http_method: HttpMethod::Get,
                path_template: "/payments".to_owned(),
                field_bindings: vec![
                    HttpFieldBinding::Query {
                        field: "status".to_owned(),
                        param: "status".to_owned(),
                    },
                    HttpFieldBinding::Query {
                        field: "currency".to_owned(),
                        param: "currency".to_owned(),
                    },
                ],
            },
        ],
    }
}
