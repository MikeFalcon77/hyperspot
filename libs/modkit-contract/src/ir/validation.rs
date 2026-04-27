use super::binding::{HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr};
use super::contract::ContractIr;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub location: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

pub fn validate_contract(ir: &ContractIr) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if ir.name.is_empty() {
        errors.push(ValidationError {
            location: "ContractIr".to_owned(),
            message: "contract name must not be empty".to_owned(),
        });
    }

    if ir.module.is_empty() {
        errors.push(ValidationError {
            location: "ContractIr".to_owned(),
            message: "module must not be empty".to_owned(),
        });
    }

    if ir.version.is_empty() {
        errors.push(ValidationError {
            location: "ContractIr".to_owned(),
            message: "version must not be empty".to_owned(),
        });
    }

    if ir.methods.is_empty() {
        errors.push(ValidationError {
            location: "ContractIr".to_owned(),
            message: "must have at least one method".to_owned(),
        });
    }

    let mut seen_names: HashSet<&str> = HashSet::new();
    for method in &ir.methods {
        if method.name.is_empty() {
            errors.push(ValidationError {
                location: format!("ContractIr.methods[{}]", method.name),
                message: "method name must not be empty".to_owned(),
            });
        } else if !seen_names.insert(&method.name) {
            errors.push(ValidationError {
                location: format!("ContractIr.methods[{0}]", method.name),
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

pub fn validate_http_binding(
    contract: &ContractIr,
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

fn validate_method_coverage(
    contract: &ContractIr,
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

fn validate_single_method_binding(
    contract: &ContractIr,
    method_binding: &HttpMethodBindingIr,
    errors: &mut Vec<ValidationError>,
) {
    let method_loc = format!("HttpBindingIr.methods[{}]", method_binding.method_name);

    validate_body_constraint(method_binding, &method_loc, errors);
    validate_path_params(method_binding, &method_loc, errors);
    validate_path_field_references(contract, method_binding, &method_loc, errors);
}

fn validate_body_constraint(
    method_binding: &HttpMethodBindingIr,
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

fn validate_path_params(
    method_binding: &HttpMethodBindingIr,
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

fn validate_path_field_references(
    contract: &ContractIr,
    method_binding: &HttpMethodBindingIr,
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
