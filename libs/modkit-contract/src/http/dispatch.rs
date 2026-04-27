use crate::error::ContractError;
use crate::ir::binding::{HttpFieldBinding, HttpMethod, HttpMethodBindingIr};

pub fn build_url(
    base_url: &str,
    base_path: &str,
    method_binding: &HttpMethodBindingIr,
    fields: &serde_json::Value,
) -> Result<String, ContractError> {
    let mut path = method_binding.path_template.clone();
    let mut query_pairs: Vec<(String, String)> = Vec::new();

    for binding in &method_binding.field_bindings {
        match binding {
            HttpFieldBinding::Path { field, param } => {
                let value = field_as_string(fields, field)?.ok_or_else(|| {
                    ContractError::Transport(
                        format!("required path parameter '{field}' is missing or null").into(),
                    )
                })?;
                path = path.replace(&format!("{{{param}}}"), &value);
            }
            HttpFieldBinding::Query { field, param } => {
                if let Some(value) = field_as_string(fields, field)? {
                    query_pairs.push((param.clone(), value));
                }
            }
            HttpFieldBinding::Body | HttpFieldBinding::Header { .. } => {}
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

#[must_use]
pub fn to_http_method(method: HttpMethod) -> http::Method {
    match method {
        HttpMethod::Get => http::Method::GET,
        HttpMethod::Post => http::Method::POST,
        HttpMethod::Put => http::Method::PUT,
        HttpMethod::Delete => http::Method::DELETE,
    }
}

fn field_as_string(
    fields: &serde_json::Value,
    field_name: &str,
) -> Result<Option<String>, ContractError> {
    let Some(value) = fields.get(field_name) else {
        return Ok(None);
    };

    match value {
        serde_json::Value::String(s) => Ok(Some(s.clone())),
        serde_json::Value::Number(n) => Ok(Some(n.to_string())),
        serde_json::Value::Bool(b) => Ok(Some(b.to_string())),
        serde_json::Value::Null => Ok(None),
        _ => Err(ContractError::Transport(
            format!("field '{field_name}' has a non-scalar type and cannot be used in URL").into(),
        )),
    }
}

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
