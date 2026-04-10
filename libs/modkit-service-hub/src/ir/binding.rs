//! Binding IR — transport-specific projection of a service contract.
//!
//! Describes *how* a service is exposed over a specific transport (HTTP, gRPC, etc.).
//! Lives in the module crate (provider-side), NOT in the SDK.
//! Keeps REST semantics out of the logical contract.

use serde::{Deserialize, Serialize};

/// HTTP binding projection for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBindingIr {
    /// Base path prefix (e.g., "/api/service-hub-demo/v1").
    pub base_path: String,
    /// Per-method HTTP bindings.
    pub methods: Vec<HttpMethodBindingIr>,
}

impl HttpBindingIr {
    /// Find the binding for a specific method by name.
    #[must_use]
    pub fn find_method(&self, method_name: &str) -> Option<&HttpMethodBindingIr> {
        self.methods.iter().find(|m| m.method_name == method_name)
    }
}

/// HTTP binding for a single method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMethodBindingIr {
    /// Method name (must match a `MethodIr.name` in the contract).
    pub method_name: String,
    /// HTTP method (GET, POST, PUT, DELETE).
    pub http_method: HttpMethod,
    /// Path template relative to `base_path` (e.g., "/payments/charge").
    /// Path parameters use `{param_name}` syntax.
    pub path_template: String,
    /// How each input field maps to the HTTP request.
    pub field_bindings: Vec<HttpFieldBinding>,
}

/// HTTP method verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
}

/// How an input field is bound to the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpFieldBinding {
    /// Field value goes into a URL path parameter.
    Path {
        /// Name of the field in `InputShape`.
        field: String,
        /// Name of the path parameter in the template.
        param: String,
    },
    /// Field value goes into a query parameter.
    Query {
        /// Name of the field in `InputShape`.
        field: String,
        /// Name of the query parameter.
        param: String,
    },
    /// Field value goes into the request body (JSON).
    Body,
    /// Field value goes into an HTTP header.
    Header {
        /// Name of the field in `InputShape`.
        field: String,
        /// Name of the HTTP header.
        header: String,
    },
}
