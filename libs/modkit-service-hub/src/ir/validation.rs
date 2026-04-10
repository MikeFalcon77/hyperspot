//! Validation functions for Contract IR and Binding IR.

use super::binding::{HttpBindingIr, HttpFieldBinding, HttpMethod};
use super::contract::ServiceIr;
use std::collections::HashSet;
use std::fmt;

/// An error found during IR validation.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Which element has the error (e.g., method name).
    pub location: String,
    /// Description of the problem.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

/// Validate a service contract IR for structural correctness.
///
/// Checks:
/// - Service name, module, and version must not be empty.
/// - Must have at least one method.
/// - Method names must be unique and non-empty.
///
/// # Errors
///
/// Returns `Vec<ValidationError>` containing all issues found if the contract
/// is invalid.
pub fn validate_contract(ir: &ServiceIr) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if ir.name.is_empty() {
        errors.push(ValidationError {
            location: "ServiceIr".to_owned(),
            message: "service name must not be empty".to_owned(),
        });
    }

    if ir.module.is_empty() {
        errors.push(ValidationError {
            location: "ServiceIr".to_owned(),
            message: "module must not be empty".to_owned(),
        });
    }

    if ir.version.is_empty() {
        errors.push(ValidationError {
            location: "ServiceIr".to_owned(),
            message: "version must not be empty".to_owned(),
        });
    }

    if ir.methods.is_empty() {
        errors.push(ValidationError {
            location: "ServiceIr".to_owned(),
            message: "must have at least one method".to_owned(),
        });
    }

    let mut seen_names: HashSet<&str> = HashSet::new();
    for method in &ir.methods {
        if method.name.is_empty() {
            errors.push(ValidationError {
                location: format!("ServiceIr.methods[{}]", method.name),
                message: "method name must not be empty".to_owned(),
            });
        } else if !seen_names.insert(&method.name) {
            errors.push(ValidationError {
                location: format!("ServiceIr.methods[{0}]", method.name),
                message: format!("duplicate method name: {}", method.name),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Extract path parameter names from an HTTP path template.
///
/// Finds all occurrences of `{param_name}` in the template and returns the
/// parameter names.
fn extract_path_params(template: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        if let Some(end) = rest[start..].find('}') {
            let param = &rest[start + 1..start + end];
            if !param.is_empty() {
                params.push(param.to_owned());
            }
            rest = &rest[start + end + 1..];
        } else {
            break;
        }
    }
    params
}

/// Validate an HTTP binding IR against its corresponding service contract IR.
///
/// Checks:
/// - Base path must not be empty.
/// - Every contract method must have a corresponding binding.
/// - No extra bindings for methods not in the contract.
/// - GET/DELETE methods must not have `Body` field bindings.
/// - Path parameters in templates must have corresponding `Path` field bindings.
/// - `Path` field bindings must reference fields that exist in the contract method input.
///
/// # Errors
///
/// Returns `Vec<ValidationError>` containing all issues found if the binding
/// is invalid.
pub fn validate_http_binding(
    contract: &ServiceIr,
    binding: &HttpBindingIr,
) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if binding.base_path.is_empty() {
        errors.push(ValidationError {
            location: "HttpBindingIr".to_owned(),
            message: "base_path must not be empty".to_owned(),
        });
    }

    validate_method_coverage(contract, binding, &mut errors);

    for method_binding in &binding.methods {
        validate_single_method_binding(contract, method_binding, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Check that every contract method has a binding and no extra bindings exist.
fn validate_method_coverage(
    contract: &ServiceIr,
    binding: &HttpBindingIr,
    errors: &mut Vec<ValidationError>,
) {
    let contract_method_names: HashSet<&str> =
        contract.methods.iter().map(|m| m.name.as_str()).collect();
    let mut binding_method_names: HashSet<&str> = HashSet::new();

    for method in &binding.methods {
        let name = method.method_name.as_str();
        if !binding_method_names.insert(name) {
            errors.push(ValidationError {
                location: format!("HttpBindingIr.methods[{name}]"),
                message: format!("duplicate binding for contract method: {name}"),
            });
        }
    }

    for name in &contract_method_names {
        if !binding_method_names.contains(name) {
            errors.push(ValidationError {
                location: format!("HttpBindingIr.methods[{name}]"),
                message: format!("missing binding for contract method: {name}"),
            });
        }
    }

    for name in &binding_method_names {
        if !contract_method_names.contains(name) {
            errors.push(ValidationError {
                location: format!("HttpBindingIr.methods[{name}]"),
                message: format!("binding for unknown method not in contract: {name}"),
            });
        }
    }
}

/// Validate a single method binding against the contract.
fn validate_single_method_binding(
    contract: &ServiceIr,
    method_binding: &super::binding::HttpMethodBindingIr,
    errors: &mut Vec<ValidationError>,
) {
    let method_loc = format!("HttpBindingIr.methods[{}]", method_binding.method_name);

    validate_body_constraint(method_binding, &method_loc, errors);
    validate_path_params(method_binding, &method_loc, errors);
    validate_path_field_references(contract, method_binding, &method_loc, errors);
}

/// Ensure GET/DELETE methods do not have `Body` field bindings.
fn validate_body_constraint(
    method_binding: &super::binding::HttpMethodBindingIr,
    method_loc: &str,
    errors: &mut Vec<ValidationError>,
) {
    if !matches!(
        method_binding.http_method,
        HttpMethod::Get | HttpMethod::Delete
    ) {
        return;
    }

    let has_body = method_binding
        .field_bindings
        .iter()
        .any(|fb| matches!(fb, HttpFieldBinding::Body));

    if has_body {
        let verb = match method_binding.http_method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        };
        errors.push(ValidationError {
            location: method_loc.to_owned(),
            message: format!("{verb} method must not have Body field binding"),
        });
    }
}

/// Ensure path template parameters have corresponding `Path` field bindings.
fn validate_path_params(
    method_binding: &super::binding::HttpMethodBindingIr,
    method_loc: &str,
    errors: &mut Vec<ValidationError>,
) {
    let template_params = extract_path_params(&method_binding.path_template);
    let path_binding_params: HashSet<&str> = method_binding
        .field_bindings
        .iter()
        .filter_map(|fb| {
            if let HttpFieldBinding::Path { param, .. } = fb {
                Some(param.as_str())
            } else {
                None
            }
        })
        .collect();

    for param in &template_params {
        if !path_binding_params.contains(param.as_str()) {
            errors.push(ValidationError {
                location: method_loc.to_owned(),
                message: format!(
                    "path template parameter '{{{param}}}' has no corresponding Path field binding"
                ),
            });
        }
    }
}

/// Ensure `Path` field bindings reference fields that exist in the contract method input.
fn validate_path_field_references(
    contract: &ServiceIr,
    method_binding: &super::binding::HttpMethodBindingIr,
    method_loc: &str,
    errors: &mut Vec<ValidationError>,
) {
    let Some(contract_method) = contract
        .methods
        .iter()
        .find(|m| m.name == method_binding.method_name)
    else {
        return;
    };

    let input_field_names: HashSet<&str> = contract_method
        .input
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();

    for fb in &method_binding.field_bindings {
        if let HttpFieldBinding::Path { field, .. } = fb
            && !input_field_names.contains(field.as_str())
        {
            errors.push(ValidationError {
                location: method_loc.to_owned(),
                message: format!(
                    "Path binding references field '{field}' not found in contract method input"
                ),
            });
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ir::binding::{HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr};
    use crate::ir::contract::{
        FieldIr, Idempotency, InputShape, MethodIr, MethodKind, PrimitiveType, ServiceIr, TypeRef,
    };

    fn sample_contract() -> ServiceIr {
        ServiceIr {
            name: "PaymentService".to_owned(),
            module: "service-hub-demo".to_owned(),
            version: "v1".to_owned(),
            methods: vec![
                MethodIr {
                    name: "charge".to_owned(),
                    kind: MethodKind::Unary,
                    input: InputShape {
                        fields: vec![FieldIr {
                            name: "request".to_owned(),
                            ty: TypeRef::Named("ChargeRequest".to_owned()),
                            optional: false,
                        }],
                    },
                    output: TypeRef::Named("ChargeResponse".to_owned()),
                    error: Some(TypeRef::Named("PaymentError".to_owned())),
                    idempotency: Idempotency::NonIdempotentWrite,
                },
                MethodIr {
                    name: "get_invoice".to_owned(),
                    kind: MethodKind::Unary,
                    input: InputShape {
                        fields: vec![FieldIr {
                            name: "invoice_id".to_owned(),
                            ty: TypeRef::Primitive(PrimitiveType::String),
                            optional: false,
                        }],
                    },
                    output: TypeRef::Named("Invoice".to_owned()),
                    error: Some(TypeRef::Named("PaymentError".to_owned())),
                    idempotency: Idempotency::SafeRead,
                },
            ],
        }
    }

    fn sample_binding() -> HttpBindingIr {
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
            ],
        }
    }

    #[test]
    fn valid_contract_passes() {
        let contract = sample_contract();
        assert!(validate_contract(&contract).is_ok());
    }

    #[test]
    fn empty_service_name_fails() {
        let mut contract = sample_contract();
        contract.name = String::new();
        let errors = validate_contract(&contract).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("service name")));
    }

    #[test]
    fn duplicate_method_names_fails() {
        let mut contract = sample_contract();
        contract.methods.push(MethodIr {
            name: "charge".to_owned(),
            kind: MethodKind::Unary,
            input: InputShape { fields: vec![] },
            output: TypeRef::Primitive(PrimitiveType::Bool),
            error: None,
            idempotency: Idempotency::NonIdempotentWrite,
        });
        let errors = validate_contract(&contract).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("duplicate method name")));
    }

    #[test]
    fn valid_http_binding_passes() {
        let contract = sample_contract();
        let binding = sample_binding();
        assert!(validate_http_binding(&contract, &binding).is_ok());
    }

    #[test]
    fn missing_binding_for_method_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        // Remove the "get_invoice" binding.
        binding.methods.retain(|m| m.method_name != "get_invoice");
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("missing binding for contract method")));
    }

    #[test]
    fn extra_binding_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        binding.methods.push(HttpMethodBindingIr {
            method_name: "refund".to_owned(),
            http_method: HttpMethod::Post,
            path_template: "/payments/refund".to_owned(),
            field_bindings: vec![HttpFieldBinding::Body],
        });
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("binding for unknown method")));
    }

    #[test]
    fn duplicate_binding_for_same_method_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        binding.methods.push(HttpMethodBindingIr {
            method_name: "charge".to_owned(),
            http_method: HttpMethod::Post,
            path_template: "/payments/charge-again".to_owned(),
            field_bindings: vec![HttpFieldBinding::Body],
        });

        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("duplicate binding for contract method")));
    }

    #[test]
    fn get_with_body_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        // Change get_invoice to have a Body binding (invalid for GET).
        for method in &mut binding.methods {
            if method.method_name == "get_invoice" {
                method.field_bindings.push(HttpFieldBinding::Body);
            }
        }
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("must not have Body field binding")));
    }

    #[test]
    fn path_param_mismatch_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        // Change get_invoice template to include {id} but keep the Path binding on {invoice_id}.
        for method in &mut binding.methods {
            if method.method_name == "get_invoice" {
                method.path_template = "/invoices/{id}".to_owned();
            }
        }
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("has no corresponding Path field binding")));
    }

    #[test]
    fn post_without_body_passes() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        // Remove Body from the charge method (POST without body should pass).
        for method in &mut binding.methods {
            if method.method_name == "charge" {
                method.field_bindings.clear();
                method.field_bindings.push(HttpFieldBinding::Query {
                    field: "request".to_owned(),
                    param: "request".to_owned(),
                });
            }
        }
        assert!(validate_http_binding(&contract, &binding).is_ok());
    }

    #[test]
    fn empty_module_fails() {
        let mut contract = sample_contract();
        contract.module = String::new();
        let errors = validate_contract(&contract).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("module")));
    }

    #[test]
    fn empty_version_fails() {
        let mut contract = sample_contract();
        contract.version = String::new();
        let errors = validate_contract(&contract).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("version")));
    }

    #[test]
    fn no_methods_fails() {
        let mut contract = sample_contract();
        contract.methods.clear();
        let errors = validate_contract(&contract).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("at least one method")));
    }

    #[test]
    fn empty_method_name_fails() {
        let mut contract = sample_contract();
        contract.methods[0].name = String::new();
        let errors = validate_contract(&contract).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("method name must not be empty")));
    }

    #[test]
    fn empty_base_path_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        binding.base_path = String::new();
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("base_path must not be empty")));
    }

    #[test]
    fn path_binding_references_nonexistent_field_fails() {
        let contract = sample_contract();
        let mut binding = sample_binding();
        for method in &mut binding.methods {
            if method.method_name == "get_invoice" {
                method.field_bindings = vec![HttpFieldBinding::Path {
                    field: "nonexistent_field".to_owned(),
                    param: "invoice_id".to_owned(),
                }];
            }
        }
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("not found in contract method input")));
    }

    #[test]
    fn method_with_zero_fields_passes() {
        let contract = ServiceIr {
            name: "HealthService".to_owned(),
            module: "health".to_owned(),
            version: "v1".to_owned(),
            methods: vec![MethodIr {
                name: "ping".to_owned(),
                kind: MethodKind::Unary,
                input: InputShape { fields: vec![] },
                output: TypeRef::Primitive(PrimitiveType::Bool),
                error: None,
                idempotency: Idempotency::SafeRead,
            }],
        };
        assert!(validate_contract(&contract).is_ok());
    }

    #[test]
    fn delete_with_body_fails() {
        let mut contract = sample_contract();
        contract.methods = vec![MethodIr {
            name: "delete_invoice".to_owned(),
            kind: MethodKind::Unary,
            input: InputShape {
                fields: vec![FieldIr {
                    name: "invoice_id".to_owned(),
                    ty: TypeRef::Primitive(PrimitiveType::String),
                    optional: false,
                }],
            },
            output: TypeRef::Primitive(PrimitiveType::Bool),
            error: None,
            idempotency: Idempotency::IdempotentWrite,
        }];
        let binding = HttpBindingIr {
            base_path: "/api/v1".to_owned(),
            methods: vec![HttpMethodBindingIr {
                method_name: "delete_invoice".to_owned(),
                http_method: HttpMethod::Delete,
                path_template: "/invoices/{invoice_id}".to_owned(),
                field_bindings: vec![
                    HttpFieldBinding::Path {
                        field: "invoice_id".to_owned(),
                        param: "invoice_id".to_owned(),
                    },
                    HttpFieldBinding::Body,
                ],
            }],
        };
        let errors = validate_http_binding(&contract, &binding).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.message.contains("must not have Body field binding")));
    }

    #[test]
    fn find_method_returns_correct_binding() {
        let binding = sample_binding();
        let found = binding.find_method("charge");
        assert!(found.is_some());
        assert_eq!(found.map(|m| &m.method_name).unwrap(), "charge");
    }

    #[test]
    fn find_method_returns_none_for_unknown() {
        let binding = sample_binding();
        assert!(binding.find_method("nonexistent").is_none());
    }

    #[test]
    fn validation_error_display() {
        let err = ValidationError {
            location: "test_location".to_owned(),
            message: "test_message".to_owned(),
        };
        assert_eq!(err.to_string(), "test_location: test_message");
    }
}
