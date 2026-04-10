//! HTTP dispatch helpers: URL construction and generic invocation.
//!
//! These functions translate Binding IR metadata into concrete HTTP
//! requests using [`modkit_http::HttpClient`].

use crate::error::ServiceHubError;
use crate::ir::binding::{HttpFieldBinding, HttpMethod, HttpMethodBindingIr};

/// Build a fully-qualified URL from base URL, base path, method binding, and field values.
///
/// Substitutes `{param}` path parameters and appends query parameters.
///
/// # Errors
///
/// Returns [`ServiceHubError::Transport`] if a required path parameter is
/// missing from `fields`.
pub fn build_url(
    base_url: &str,
    base_path: &str,
    method_binding: &HttpMethodBindingIr,
    fields: &serde_json::Value,
) -> Result<String, ServiceHubError> {
    // Start with base_url + base_path + path_template.
    let mut path = method_binding.path_template.clone();

    let mut query_pairs: Vec<(String, String)> = Vec::new();

    for binding in &method_binding.field_bindings {
        match binding {
            HttpFieldBinding::Path { field, param } => {
                let value = field_as_string(fields, field)?;
                path = path.replace(&format!("{{{param}}}"), &value);
            }
            HttpFieldBinding::Query { field, param } => {
                let value = field_as_string(fields, field)?;
                query_pairs.push((param.clone(), value));
            }
            HttpFieldBinding::Body | HttpFieldBinding::Header { .. } => {
                // Handled at the call site, not in URL construction.
            }
        }
    }

    let base = base_url.trim_end_matches('/');
    let base_p = base_path.trim_end_matches('/');
    let mut url = format!("{base}{base_p}{path}");

    if !query_pairs.is_empty() {
        url.push('?');
        for (i, (key, value)) in query_pairs.iter().enumerate() {
            if i > 0 {
                url.push('&');
            }
            url.push_str(key);
            url.push('=');
            url.push_str(&urlencoded_value(value));
        }
    }

    Ok(url)
}

/// Convert an [`HttpMethod`] to an [`http::Method`].
#[must_use]
pub fn to_http_method(method: HttpMethod) -> http::Method {
    match method {
        HttpMethod::Get => http::Method::GET,
        HttpMethod::Post => http::Method::POST,
        HttpMethod::Put => http::Method::PUT,
        HttpMethod::Delete => http::Method::DELETE,
    }
}

/// Extract a field value from a JSON object as a string suitable for URL embedding.
fn field_as_string(
    fields: &serde_json::Value,
    field_name: &str,
) -> Result<String, ServiceHubError> {
    let value = fields.get(field_name).ok_or_else(|| {
        ServiceHubError::Transport(
            format!("missing field '{field_name}' in request for URL construction").into(),
        )
    })?;

    // Convert to a URL-safe string representation.
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        _ => Err(ServiceHubError::Transport(
            format!("field '{field_name}' has a non-scalar type and cannot be used in URL")
                .into(),
        )),
    }
}

/// Minimal percent-encoding for query parameter values.
fn urlencoded_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            ' ' => out.push_str("%20"),
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '+' => out.push_str("%2B"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ir::binding::{HttpFieldBinding, HttpMethod, HttpMethodBindingIr};
    use serde_json::json;

    #[test]
    fn build_url_with_path_params() {
        let binding = HttpMethodBindingIr {
            method_name: "get_invoice".to_owned(),
            http_method: HttpMethod::Get,
            path_template: "/invoices/{invoice_id}".to_owned(),
            field_bindings: vec![HttpFieldBinding::Path {
                field: "invoice_id".to_owned(),
                param: "invoice_id".to_owned(),
            }],
        };

        let fields = json!({ "invoice_id": "inv-123" });
        let url = build_url(
            "http://billing:8080",
            "/api/v1",
            &binding,
            &fields,
        )
        .unwrap();

        assert_eq!(url, "http://billing:8080/api/v1/invoices/inv-123");
    }

    #[test]
    fn build_url_with_query_params() {
        let binding = HttpMethodBindingIr {
            method_name: "list_invoices".to_owned(),
            http_method: HttpMethod::Get,
            path_template: "/invoices".to_owned(),
            field_bindings: vec![
                HttpFieldBinding::Query {
                    field: "status".to_owned(),
                    param: "status".to_owned(),
                },
                HttpFieldBinding::Query {
                    field: "limit".to_owned(),
                    param: "limit".to_owned(),
                },
            ],
        };

        let fields = json!({ "status": "paid", "limit": 50 });
        let url = build_url(
            "http://billing:8080",
            "/api/v1",
            &binding,
            &fields,
        )
        .unwrap();

        assert_eq!(url, "http://billing:8080/api/v1/invoices?status=paid&limit=50");
    }

    #[test]
    fn build_url_path_and_query_combined() {
        let binding = HttpMethodBindingIr {
            method_name: "get_line_items".to_owned(),
            http_method: HttpMethod::Get,
            path_template: "/invoices/{invoice_id}/items".to_owned(),
            field_bindings: vec![
                HttpFieldBinding::Path {
                    field: "invoice_id".to_owned(),
                    param: "invoice_id".to_owned(),
                },
                HttpFieldBinding::Query {
                    field: "page".to_owned(),
                    param: "page".to_owned(),
                },
            ],
        };

        let fields = json!({ "invoice_id": "inv-456", "page": 2 });
        let url = build_url(
            "http://billing:8080",
            "/api/v1",
            &binding,
            &fields,
        )
        .unwrap();

        assert_eq!(
            url,
            "http://billing:8080/api/v1/invoices/inv-456/items?page=2"
        );
    }

    #[test]
    fn build_url_missing_field_returns_error() {
        let binding = HttpMethodBindingIr {
            method_name: "get_invoice".to_owned(),
            http_method: HttpMethod::Get,
            path_template: "/invoices/{invoice_id}".to_owned(),
            field_bindings: vec![HttpFieldBinding::Path {
                field: "invoice_id".to_owned(),
                param: "invoice_id".to_owned(),
            }],
        };

        let fields = json!({});
        let err = build_url(
            "http://billing:8080",
            "/api/v1",
            &binding,
            &fields,
        )
        .unwrap_err();

        assert!(matches!(err, ServiceHubError::Transport(_)));
    }

    #[test]
    fn build_url_body_binding_is_ignored() {
        let binding = HttpMethodBindingIr {
            method_name: "charge".to_owned(),
            http_method: HttpMethod::Post,
            path_template: "/payments/charge".to_owned(),
            field_bindings: vec![HttpFieldBinding::Body],
        };

        let fields = json!({ "amount": 100 });
        let url = build_url(
            "http://billing:8080",
            "/api/v1",
            &binding,
            &fields,
        )
        .unwrap();

        assert_eq!(url, "http://billing:8080/api/v1/payments/charge");
    }

    #[test]
    fn to_http_method_maps_correctly() {
        assert_eq!(to_http_method(HttpMethod::Get), http::Method::GET);
        assert_eq!(to_http_method(HttpMethod::Post), http::Method::POST);
        assert_eq!(to_http_method(HttpMethod::Put), http::Method::PUT);
        assert_eq!(to_http_method(HttpMethod::Delete), http::Method::DELETE);
    }

    #[test]
    fn build_url_trailing_slashes_are_normalized() {
        let binding = HttpMethodBindingIr {
            method_name: "ping".to_owned(),
            http_method: HttpMethod::Get,
            path_template: "/health".to_owned(),
            field_bindings: vec![],
        };

        let fields = json!({});
        let url = build_url(
            "http://billing:8080/",
            "/api/v1/",
            &binding,
            &fields,
        )
        .unwrap();

        assert_eq!(url, "http://billing:8080/api/v1/health");
    }

    #[test]
    fn query_value_encoding() {
        let binding = HttpMethodBindingIr {
            method_name: "search".to_owned(),
            http_method: HttpMethod::Get,
            path_template: "/search".to_owned(),
            field_bindings: vec![HttpFieldBinding::Query {
                field: "q".to_owned(),
                param: "q".to_owned(),
            }],
        };

        let fields = json!({ "q": "hello world&more" });
        let url = build_url(
            "http://svc:8080",
            "/api",
            &binding,
            &fields,
        )
        .unwrap();

        assert_eq!(url, "http://svc:8080/api/search?q=hello%20world%26more");
    }
}
