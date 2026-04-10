//! Build OpenAPI 3.1 documents from `ContractIr` + `HttpBindingIr`.

use serde_json::{Value, json};

use crate::ir::binding::{HttpBindingIr, HttpFieldBinding, HttpMethod, HttpMethodBindingIr};
use crate::ir::contract::{ContractIr, MethodIr, PrimitiveType, TypeRef};

/// A named schema definition supplied by the caller. Typically produced by
/// `schemars::schema_for!(MyType)` and converted to `serde_json::Value`.
pub type SchemaEntry<'a> = (&'a str, Value);

/// Generate an OpenAPI 3.1 document.
///
/// `schemas` are placed under `components.schemas`. The generator does not
/// introspect domain types — it relies entirely on the names declared in
/// `MethodIr.input` / `MethodIr.output` / `MethodIr.error` matching the
/// names supplied by the caller.
#[must_use]
pub fn generate_openapi_spec(
    contract: &ContractIr,
    binding: &HttpBindingIr,
    schemas: &[SchemaEntry<'_>],
) -> Value {
    let mut paths = serde_json::Map::new();

    for method_binding in &binding.methods {
        let Some(method_ir) = contract
            .methods
            .iter()
            .find(|m| m.name == method_binding.method_name)
        else {
            continue;
        };
        let path = format!(
            "{}{}",
            binding.base_path.trim_end_matches('/'),
            method_binding.path_template
        );
        let verb = http_method_lowercase(method_binding.http_method);

        let entry = paths
            .entry(path)
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Object(map) = entry {
            map.insert(
                verb.to_owned(),
                build_operation(method_ir, method_binding, &contract.module),
            );
        }
    }

    let components = build_components(schemas);

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": contract.name,
            "version": contract.version,
            "x-module": contract.module,
        },
        "paths": Value::Object(paths),
        "components": components,
    })
}

fn build_operation(method: &MethodIr, binding: &HttpMethodBindingIr, module: &str) -> Value {
    let mut op = serde_json::Map::new();
    op.insert(
        "operationId".to_owned(),
        Value::String(format!("{module}_{}", method.name)),
    );

    let mut tags = Vec::new();
    tags.push(Value::String(module.to_owned()));
    op.insert("tags".to_owned(), Value::Array(tags));

    let parameters = build_parameters(method, binding);
    if !parameters.is_empty() {
        op.insert("parameters".to_owned(), Value::Array(parameters));
    }

    if let Some(request_body) = build_request_body(method, binding) {
        op.insert("requestBody".to_owned(), request_body);
    }

    op.insert("responses".to_owned(), build_responses(method, binding));

    if binding.retryable {
        op.insert("x-retryable".to_owned(), Value::Bool(true));
    }
    if binding.streaming {
        op.insert("x-streaming".to_owned(), Value::Bool(true));
    }
    if binding.optional || method.optional {
        op.insert("x-optional".to_owned(), Value::Bool(true));
        op.insert(
            "description".to_owned(),
            Value::String(
                "Optional endpoint — peers MAY omit this method.".to_owned(),
            ),
        );
    }

    Value::Object(op)
}

fn build_parameters(method: &MethodIr, binding: &HttpMethodBindingIr) -> Vec<Value> {
    let mut params = Vec::new();
    for fb in &binding.field_bindings {
        match fb {
            HttpFieldBinding::Path { field, param } => {
                params.push(parameter_object(
                    "path",
                    param,
                    field_schema(method, field),
                    /* required = */ true,
                ));
            }
            HttpFieldBinding::Query { field, param } => {
                params.push(parameter_object(
                    "query",
                    param,
                    field_schema(method, field),
                    /* required = */ false,
                ));
            }
            HttpFieldBinding::Header { field, header } => {
                params.push(parameter_object(
                    "header",
                    header,
                    field_schema(method, field),
                    /* required = */ false,
                ));
            }
            HttpFieldBinding::Body => {}
        }
    }
    params
}

fn parameter_object(loc: &str, name: &str, schema: Value, required: bool) -> Value {
    json!({
        "name": name,
        "in": loc,
        "required": required,
        "schema": schema,
    })
}

fn field_schema(method: &MethodIr, field_name: &str) -> Value {
    let Some(field) = method.input.fields.iter().find(|f| f.name == field_name) else {
        return json!({ "type": "string" });
    };
    typeref_to_schema(&field.ty)
}

fn typeref_to_schema(ty: &TypeRef) -> Value {
    match ty {
        TypeRef::Primitive(p) => primitive_to_schema(*p),
        TypeRef::Named(name) => json!({ "$ref": format!("#/components/schemas/{name}") }),
        TypeRef::Optional(inner) => typeref_to_schema(inner),
        TypeRef::List(inner) => json!({
            "type": "array",
            "items": typeref_to_schema(inner),
        }),
        TypeRef::Map(key, value) => json!({
            "type": "object",
            "additionalProperties": typeref_to_schema(value),
            "x-key-schema": typeref_to_schema(key),
        }),
    }
}

fn primitive_to_schema(p: PrimitiveType) -> Value {
    match p {
        PrimitiveType::String => json!({ "type": "string" }),
        PrimitiveType::Bool => json!({ "type": "boolean" }),
        PrimitiveType::Bytes => json!({ "type": "string", "format": "byte" }),
        PrimitiveType::Uuid => json!({ "type": "string", "format": "uuid" }),
        PrimitiveType::I32 => json!({ "type": "integer", "format": "int32" }),
        PrimitiveType::I64 => json!({ "type": "integer", "format": "int64" }),
        PrimitiveType::U64 => json!({ "type": "integer", "format": "int64", "minimum": 0 }),
        PrimitiveType::F64 => json!({ "type": "number", "format": "double" }),
    }
}

fn build_request_body(method: &MethodIr, binding: &HttpMethodBindingIr) -> Option<Value> {
    let has_body = binding
        .field_bindings
        .iter()
        .any(|fb| matches!(fb, HttpFieldBinding::Body));
    if !has_body {
        return None;
    }
    let body_field = method.input.fields.iter().find(|f| {
        binding.field_bindings.iter().any(|fb| matches!(fb, HttpFieldBinding::Body))
            && !is_path_or_query_field(&binding.field_bindings, &f.name)
    })?;
    let schema = typeref_to_schema(&body_field.ty);
    Some(json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": schema,
            }
        }
    }))
}

fn is_path_or_query_field(bindings: &[HttpFieldBinding], field_name: &str) -> bool {
    bindings.iter().any(|fb| match fb {
        HttpFieldBinding::Path { field, .. }
        | HttpFieldBinding::Query { field, .. }
        | HttpFieldBinding::Header { field, .. } => field == field_name,
        HttpFieldBinding::Body => false,
    })
}

fn build_responses(method: &MethodIr, binding: &HttpMethodBindingIr) -> Value {
    let mut responses = serde_json::Map::new();

    let success_schema = typeref_to_schema(&method.output);
    let success_content_type = if binding.streaming {
        "text/event-stream"
    } else {
        "application/json"
    };
    responses.insert(
        "200".to_owned(),
        json!({
            "description": "Successful response",
            "content": {
                success_content_type: { "schema": success_schema },
            }
        }),
    );

    responses.insert(
        "default".to_owned(),
        json!({
            "description": "Error response (RFC 9457 Problem)",
            "content": {
                "application/problem+json": {
                    "schema": { "$ref": "#/components/schemas/Problem" },
                }
            }
        }),
    );

    Value::Object(responses)
}

fn build_components(schemas: &[SchemaEntry<'_>]) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("Problem".to_owned(), canonical_problem_schema());
    for (name, schema) in schemas {
        map.insert((*name).to_owned(), schema.clone());
    }
    json!({ "schemas": Value::Object(map) })
}

/// OpenAPI schema for `modkit_canonical_errors::Problem` — RFC 9457
/// Problem Details with the CyberFabric extension members `trace_id` and
/// `context` as documented in `docs/arch/errors/DESIGN.md` §3.3.
fn canonical_problem_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "title", "status", "detail", "context"],
        "properties": {
            "type": {
                "type": "string",
                "description": "GTS type identifier for the canonical error category"
            },
            "title": {
                "type": "string",
                "description": "Human-readable category title"
            },
            "status": {
                "type": "integer",
                "description": "HTTP status code from the category mapping"
            },
            "detail": {
                "type": "string",
                "description": "Human-readable explanation of this occurrence"
            },
            "instance": {
                "type": "string",
                "description": "URI identifying this specific occurrence"
            },
            "trace_id": {
                "type": "string",
                "description": "W3C trace ID for correlation, injected by middleware"
            },
            "context": {
                "type": "object",
                "description": "Category-specific structured details"
            }
        }
    })
}

fn http_method_lowercase(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Delete => "delete",
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ir::binding::{HttpFieldBinding, HttpMethod, HttpMethodBindingIr};
    use crate::ir::contract::{
        FieldIr, Idempotency, InputShape, MethodIr, MethodKind, ServiceIr, TypeRef,
    };

    fn sample_contract() -> ContractIr {
        ServiceIr {
            name: "PaymentService".into(),
            module: "payment".into(),
            version: "v1".into(),
            methods: vec![
                MethodIr {
                    name: "charge".into(),
                    kind: MethodKind::Unary,
                    input: InputShape {
                        fields: vec![FieldIr {
                            name: "req".into(),
                            ty: TypeRef::Named("ChargeRequest".into()),
                            optional: false,
                        }],
                    },
                    output: TypeRef::Named("ChargeResponse".into()),
                    error: Some(TypeRef::Named("PaymentError".into())),
                    idempotency: Idempotency::NonIdempotentWrite,
                    optional: false,
                },
                MethodIr {
                    name: "get_invoice".into(),
                    kind: MethodKind::Unary,
                    input: InputShape {
                        fields: vec![FieldIr {
                            name: "invoice_id".into(),
                            ty: TypeRef::Primitive(PrimitiveType::String),
                            optional: false,
                        }],
                    },
                    output: TypeRef::Named("Invoice".into()),
                    error: Some(TypeRef::Named("PaymentError".into())),
                    idempotency: Idempotency::SafeRead,
                    optional: false,
                },
            ],
        }
    }

    fn sample_binding() -> HttpBindingIr {
        HttpBindingIr {
            base_path: "/api/payment/v1".into(),
            methods: vec![
                HttpMethodBindingIr {
                    method_name: "charge".into(),
                    http_method: HttpMethod::Post,
                    path_template: "/charge".into(),
                    field_bindings: vec![HttpFieldBinding::Body],
                    retryable: false,
                    streaming: false,
                    optional: false,
                },
                HttpMethodBindingIr {
                    method_name: "get_invoice".into(),
                    http_method: HttpMethod::Get,
                    path_template: "/invoices/{invoice_id}".into(),
                    field_bindings: vec![HttpFieldBinding::Path {
                        field: "invoice_id".into(),
                        param: "invoice_id".into(),
                    }],
                    retryable: true,
                    streaming: false,
                    optional: false,
                },
            ],
        }
    }

    #[test]
    fn produces_openapi_3_1_envelope() {
        let spec = generate_openapi_spec(&sample_contract(), &sample_binding(), &[]);
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "PaymentService");
        assert_eq!(spec["info"]["version"], "v1");
        assert_eq!(spec["info"]["x-module"], "payment");
    }

    #[test]
    fn registers_path_per_binding() {
        let spec = generate_openapi_spec(&sample_contract(), &sample_binding(), &[]);
        assert!(spec["paths"]["/api/payment/v1/charge"].is_object());
        assert!(spec["paths"]["/api/payment/v1/invoices/{invoice_id}"].is_object());
    }

    #[test]
    fn maps_post_to_request_body() {
        let spec = generate_openapi_spec(&sample_contract(), &sample_binding(), &[]);
        let op = &spec["paths"]["/api/payment/v1/charge"]["post"];
        assert!(op["requestBody"].is_object());
        let schema = &op["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(schema["$ref"], "#/components/schemas/ChargeRequest");
    }

    #[test]
    fn marks_retryable_with_extension() {
        let spec = generate_openapi_spec(&sample_contract(), &sample_binding(), &[]);
        let op = &spec["paths"]["/api/payment/v1/invoices/{invoice_id}"]["get"];
        assert_eq!(op["x-retryable"], true);
    }

    #[test]
    fn includes_problem_details_schema() {
        let spec = generate_openapi_spec(&sample_contract(), &sample_binding(), &[]);
        assert!(spec["components"]["schemas"]["Problem"].is_object());
    }

    #[test]
    fn merges_user_supplied_schemas() {
        let charge_request_schema = json!({
            "type": "object",
            "properties": { "amount_cents": { "type": "integer" } },
        });
        let spec = generate_openapi_spec(
            &sample_contract(),
            &sample_binding(),
            &[("ChargeRequest", charge_request_schema)],
        );
        assert_eq!(
            spec["components"]["schemas"]["ChargeRequest"]["type"],
            "object"
        );
    }

    #[test]
    fn streaming_flag_emits_event_stream_content_type() {
        let mut binding = sample_binding();
        binding.methods[0].streaming = true;
        let spec = generate_openapi_spec(&sample_contract(), &binding, &[]);
        let op = &spec["paths"]["/api/payment/v1/charge"]["post"];
        assert!(op["responses"]["200"]["content"]["text/event-stream"].is_object());
        assert_eq!(op["x-streaming"], true);
    }
}
