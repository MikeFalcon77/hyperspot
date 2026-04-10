//! Code generation from the internal model.
//!
//! Produces the trait definition (with `#[async_trait]`), the static
//! [`ServiceDescriptor`], the IR builder function, and the
//! [`ServiceContract`] impl.

use heck::{ToShoutySnakeCase, ToSnakeCase};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::model::{Idempotency, MethodKind, MethodModel, ServiceContractModel};

/// Generate all output tokens from a parsed [`ServiceContractModel`].
pub fn generate(model: &ServiceContractModel) -> TokenStream {
    let trait_def = generate_trait(model);
    let descriptor = generate_descriptor(model);
    let ir_fn = generate_ir_function(model);
    let contract_impl = generate_service_contract_impl(model);

    quote! {
        #trait_def
        #descriptor
        #ir_fn
        #contract_impl
    }
}

// ---------------------------------------------------------------------------
// 1. Trait definition
// ---------------------------------------------------------------------------

/// Emit the trait with `#[async_trait]` and streaming return types rewritten.
fn generate_trait(model: &ServiceContractModel) -> TokenStream {
    let vis = &model.vis;
    let name = &model.trait_name;
    let supertraits = &model.supertraits;
    let attrs = &model.attrs;

    let methods: Vec<TokenStream> = model.methods.iter().map(generate_trait_method).collect();

    quote! {
        #(#attrs)*
        #[::async_trait::async_trait]
        #vis trait #name: #supertraits {
            #(#methods)*
        }
    }
}

/// Emit a single trait method, rewriting streaming return types.
fn generate_trait_method(method: &MethodModel) -> TokenStream {
    let attrs = &method.attrs;
    let mut sig = method.sig.clone();

    match method.kind {
        MethodKind::Unary => {
            // Unary: keep the signature as-is (async fn ... -> Result<T, E>)
        }
        MethodKind::ServerStreaming => {
            // Streaming: rewrite return type from Result<T, E> to
            // Pin<Box<dyn Stream<Item = Result<T, E>> + Send + 'static>>
            let output = &method.output_type;
            let error = &method.error_type;

            sig.output = syn::parse_quote! {
                -> ::std::pin::Pin<Box<
                    dyn ::futures_core::Stream<Item = Result<#output, #error>> + Send + 'static
                >>
            };
        }
    }

    quote! {
        #(#attrs)*
        #sig;
    }
}

// ---------------------------------------------------------------------------
// 2. Static ServiceDescriptor
// ---------------------------------------------------------------------------

/// Emit the `SCREAMING_SNAKE_DESCRIPTOR` static.
fn generate_descriptor(model: &ServiceContractModel) -> TokenStream {
    let trait_name = &model.trait_name;
    let trait_name_str = trait_name.to_string();
    let descriptor_name = format_ident!("{}_DESCRIPTOR", trait_name_str.to_shouty_snake_case());
    let module = &model.module;
    let version = &model.version;
    let vis = &model.vis;

    let method_descriptors: Vec<TokenStream> = model
        .methods
        .iter()
        .map(|m| {
            let name_str = m.name.to_string();
            let kind = method_kind_tokens(m.kind);
            let idempotency = idempotency_tokens(m.idempotency);
            let input_type_str = m
                .params
                .last()
                .map(|p| type_name_str(&p.ty))
                .unwrap_or_default();
            let output_type_str = type_name_str(&m.output_type);

            quote! {
                ::modkit_service_hub::descriptor::MethodDescriptor {
                    name: #name_str,
                    kind: #kind,
                    idempotency: #idempotency,
                    input_type: #input_type_str,
                    output_type: #output_type_str,
                }
            }
        })
        .collect();

    let trait_doc = format!("Static descriptor for [`{trait_name_str}`].");
    quote! {
        #[doc = #trait_doc]
        #vis static #descriptor_name: ::modkit_service_hub::descriptor::ServiceDescriptor =
            ::modkit_service_hub::descriptor::ServiceDescriptor {
                module: #module,
                service: #trait_name_str,
                version: #version,
                methods: &[
                    #(#method_descriptors),*
                ],
            };
    }
}

// ---------------------------------------------------------------------------
// 3. IR builder function
// ---------------------------------------------------------------------------

/// Emit the `snake_case_ir()` function.
fn generate_ir_function(model: &ServiceContractModel) -> TokenStream {
    let trait_name = &model.trait_name;
    let trait_name_str = trait_name.to_string();
    let fn_name = format_ident!("{}_ir", trait_name_str.to_snake_case());
    let module = &model.module;
    let version = &model.version;
    let vis = &model.vis;

    let method_irs: Vec<TokenStream> = model.methods.iter().map(generate_method_ir).collect();

    let fn_doc = format!("Build the Contract IR for [`{trait_name_str}`].");
    quote! {
        #[doc = #fn_doc]
        #[must_use]
        #vis fn #fn_name() -> ::modkit_service_hub::ir::contract::ServiceIr {
            ::modkit_service_hub::ir::contract::ServiceIr {
                name: #trait_name_str.to_owned(),
                module: #module.to_owned(),
                version: #version.to_owned(),
                methods: vec![
                    #(#method_irs),*
                ],
            }
        }
    }
}

/// Emit a single `MethodIr { ... }` expression.
fn generate_method_ir(method: &MethodModel) -> TokenStream {
    let name_str = method.name.to_string();
    let kind = method_kind_tokens(method.kind);
    let idempotency = idempotency_tokens(method.idempotency);

    let fields: Vec<TokenStream> = method
        .params
        .iter()
        .map(|p| {
            let p_name = p.name.to_string();
            let ty_ref = type_to_typeref(&p.ty);
            let is_optional = is_option_type(&p.ty);
            quote! {
                ::modkit_service_hub::ir::contract::FieldIr {
                    name: #p_name.to_owned(),
                    ty: #ty_ref,
                    optional: #is_optional,
                }
            }
        })
        .collect();

    let output_ref = type_to_typeref(&method.output_type);
    let error_ref = type_to_typeref(&method.error_type);

    quote! {
        ::modkit_service_hub::ir::contract::MethodIr {
            name: #name_str.to_owned(),
            kind: #kind,
            input: ::modkit_service_hub::ir::contract::InputShape {
                fields: vec![
                    #(#fields),*
                ],
            },
            output: #output_ref,
            error: Some(#error_ref),
            idempotency: #idempotency,
        }
    }
}

// ---------------------------------------------------------------------------
// 4. ServiceContract impl
// ---------------------------------------------------------------------------

/// Emit the `ServiceContract` impl for `dyn TraitName`.
fn generate_service_contract_impl(model: &ServiceContractModel) -> TokenStream {
    let trait_name = &model.trait_name;
    let trait_name_str = trait_name.to_string();
    let descriptor_name = format_ident!("{}_DESCRIPTOR", trait_name_str.to_shouty_snake_case());
    let fn_name = format_ident!("{}_ir", trait_name_str.to_snake_case());

    quote! {
        impl ::modkit_service_hub::contract_trait::ServiceContract for dyn #trait_name {
            fn descriptor() -> &'static ::modkit_service_hub::descriptor::ServiceDescriptor {
                &#descriptor_name
            }
            fn contract_ir() -> ::modkit_service_hub::ir::contract::ServiceIr {
                #fn_name()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a [`MethodKind`] to its fully-qualified token representation.
fn method_kind_tokens(kind: MethodKind) -> TokenStream {
    match kind {
        MethodKind::Unary => {
            quote!(::modkit_service_hub::ir::contract::MethodKind::Unary)
        }
        MethodKind::ServerStreaming => {
            quote!(::modkit_service_hub::ir::contract::MethodKind::ServerStreaming)
        }
    }
}

/// Convert an [`Idempotency`] to its fully-qualified token representation.
fn idempotency_tokens(idempotency: Idempotency) -> TokenStream {
    match idempotency {
        Idempotency::SafeRead => {
            quote!(::modkit_service_hub::ir::contract::Idempotency::SafeRead)
        }
        Idempotency::IdempotentWrite => {
            quote!(::modkit_service_hub::ir::contract::Idempotency::IdempotentWrite)
        }
        Idempotency::NonIdempotentWrite => {
            quote!(::modkit_service_hub::ir::contract::Idempotency::NonIdempotentWrite)
        }
    }
}

/// Convert a `syn::Type` to a token stream that constructs a `TypeRef`.
fn type_to_typeref(ty: &syn::Type) -> TokenStream {
    let ir = quote!(::modkit_service_hub::ir::contract);

    if let syn::Type::Path(type_path) = ty
        && let Some(last_seg) = type_path.path.segments.last()
    {
        let ident_str = last_seg.ident.to_string();
        match ident_str.as_str() {
            "String" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::String));
            }
            "i32" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::I32));
            }
            "i64" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::I64));
            }
            "u64" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::U64));
            }
            "f64" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::F64));
            }
            "bool" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::Bool));
            }
            "Uuid" => {
                return quote!(#ir::TypeRef::Primitive(#ir::PrimitiveType::Uuid));
            }
            "Option" => {
                if let Some(inner) = extract_single_generic_arg(last_seg) {
                    let inner_ref = type_to_typeref(inner);
                    return quote!(#ir::TypeRef::Optional(Box::new(#inner_ref)));
                }
            }
            "Vec" => {
                if let Some(inner) = extract_single_generic_arg(last_seg) {
                    let inner_ref = type_to_typeref(inner);
                    return quote!(#ir::TypeRef::List(Box::new(#inner_ref)));
                }
            }
            other => {
                let name = (*other).to_owned();
                return quote!(#ir::TypeRef::Named(#name.to_owned()));
            }
        }
    }

    // Fallback: stringify the type
    let name = quote!(#ty).to_string();
    quote!(::modkit_service_hub::ir::contract::TypeRef::Named(#name.to_owned()))
}

/// Extract the single generic type argument from a path segment
/// (e.g., `Option<T>` -> `T`, `Vec<T>` -> `T`).
fn extract_single_generic_arg(seg: &syn::PathSegment) -> Option<&syn::Type> {
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let first = args.args.first()?;
    let syn::GenericArgument::Type(ty) = first else {
        return None;
    };
    Some(ty)
}

/// Check whether a type is `Option<T>`.
fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty
        && let Some(last_seg) = type_path.path.segments.last()
    {
        return last_seg.ident == "Option";
    }
    false
}

/// Extract a human-readable type name string for the descriptor.
fn type_name_str(ty: &syn::Type) -> String {
    if let syn::Type::Path(type_path) = ty
        && let Some(last_seg) = type_path.path.segments.last()
    {
        return last_seg.ident.to_string();
    }
    quote!(#ty).to_string()
}
