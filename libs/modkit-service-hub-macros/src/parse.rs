//! Parsing logic for the `#[service_contract]` attribute macro.
//!
//! Converts `syn` AST nodes into the internal [`ServiceContractModel`].

use syn::spanned::Spanned;
use syn::{FnArg, ItemTrait, Meta, Pat, ReturnType, TraitItem, TraitItemFn, Type};

use crate::model::{Idempotency, MethodKind, MethodModel, ParamModel, ServiceContractModel};

/// Parsed attribute parameters for `#[service_contract(module = "...", version = "...")]`.
pub struct ContractAttr {
    /// Module name.
    pub module: String,
    /// API version.
    pub version: String,
}

/// Custom keyword tokens for the attribute parser.
mod kw {
    syn::custom_keyword!(module);
    syn::custom_keyword!(version);
}

impl syn::parse::Parse for ContractAttr {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let mut module: Option<String> = None;
        let mut version: Option<String> = None;

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::module) {
                let _kw = input.parse::<kw::module>()?;
                let _eq = input.parse::<syn::Token![=]>()?;
                let lit = input.parse::<syn::LitStr>()?;
                if module.is_some() {
                    return Err(syn::Error::new(lit.span(), "duplicate `module` parameter"));
                }
                module = Some(lit.value());
            } else if lookahead.peek(kw::version) {
                let _kw = input.parse::<kw::version>()?;
                let _eq = input.parse::<syn::Token![=]>()?;
                let lit = input.parse::<syn::LitStr>()?;
                if version.is_some() {
                    return Err(syn::Error::new(lit.span(), "duplicate `version` parameter"));
                }
                version = Some(lit.value());
            } else {
                return Err(lookahead.error());
            }

            // Consume optional comma separator
            if input.peek(syn::Token![,]) {
                let _comma = input.parse::<syn::Token![,]>()?;
            }
        }

        let module =
            module.ok_or_else(|| input.error("missing required `module = \"...\"` parameter"))?;
        let version =
            version.ok_or_else(|| input.error("missing required `version = \"...\"` parameter"))?;

        Ok(Self { module, version })
    }
}

/// Parse an [`ItemTrait`] into a [`ServiceContractModel`].
///
/// # Errors
///
/// Returns a compile error if:
/// - A method does not return `Result<T, E>`
/// - `#[streaming]` is used on an `async fn`
/// - An unknown `#[idempotency(...)]` variant is encountered
pub fn parse_trait(attr: ContractAttr, item: &ItemTrait) -> syn::Result<ServiceContractModel> {
    let mut methods = Vec::new();

    for trait_item in &item.items {
        let TraitItem::Fn(method) = trait_item else {
            continue;
        };
        methods.push(parse_method(method)?);
    }

    // Preserve attributes that are NOT consumed by the macro (doc comments, cfg, etc.)
    let attrs = item.attrs.clone();

    Ok(ServiceContractModel {
        module: attr.module,
        version: attr.version,
        trait_name: item.ident.clone(),
        vis: item.vis.clone(),
        supertraits: item.supertraits.clone(),
        methods,
        attrs,
    })
}

/// Parse a single trait method into a [`MethodModel`].
fn parse_method(method: &TraitItemFn) -> syn::Result<MethodModel> {
    let sig = &method.sig;
    let name = sig.ident.clone();

    // Detect #[streaming] and #[idempotency(...)] attributes
    let is_streaming = has_attr(&method.attrs, "streaming");
    let idempotency = parse_idempotency(&method.attrs)?;

    // Validate: #[streaming] must NOT be on async fn
    if is_streaming && sig.asyncness.is_some() {
        return Err(syn::Error::new(
            sig.asyncness.span(),
            "#[streaming] methods must not be `async fn`; use `fn` instead",
        ));
    }

    let kind = if is_streaming {
        MethodKind::ServerStreaming
    } else {
        MethodKind::Unary
    };

    // Parse parameters (skip &self)
    let params = parse_params(&sig.inputs)?;

    // Parse return type
    let (output_type, error_type) = parse_return_type(&sig.output, sig.ident.span())?;

    // Collect preserved attributes (strip #[streaming] and #[idempotency(...)])
    let attrs = method
        .attrs
        .iter()
        .filter(|a| !is_macro_attr(a))
        .cloned()
        .collect();

    Ok(MethodModel {
        name,
        kind,
        idempotency,
        params,
        output_type,
        error_type,
        attrs,
        sig: sig.clone(),
    })
}

/// Check whether an attribute list contains a given simple attribute name.
fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

/// Returns `true` if this attribute is consumed by the macro
/// (`streaming` or `idempotency`).
fn is_macro_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("streaming") || attr.path().is_ident("idempotency")
}

/// Parse `#[idempotency(Variant)]` from an attribute list.
///
/// Defaults to `NonIdempotentWrite` if not present.
fn parse_idempotency(attrs: &[syn::Attribute]) -> syn::Result<Idempotency> {
    for attr in attrs {
        if !attr.path().is_ident("idempotency") {
            continue;
        }

        let Meta::List(meta_list) = &attr.meta else {
            return Err(syn::Error::new_spanned(
                attr,
                "expected #[idempotency(SafeRead)], #[idempotency(IdempotentWrite)], or #[idempotency(NonIdempotentWrite)]",
            ));
        };

        let variant: syn::Ident = syn::parse2(meta_list.tokens.clone())?;
        return match variant.to_string().as_str() {
            "SafeRead" => Ok(Idempotency::SafeRead),
            "IdempotentWrite" => Ok(Idempotency::IdempotentWrite),
            "NonIdempotentWrite" => Ok(Idempotency::NonIdempotentWrite),
            other => Err(syn::Error::new(
                variant.span(),
                format!(
                    "unknown idempotency variant `{other}`; \
                     expected SafeRead, IdempotentWrite, or NonIdempotentWrite"
                ),
            )),
        };
    }

    // Default
    Ok(Idempotency::NonIdempotentWrite)
}

/// Parse method parameters, skipping `&self`.
fn parse_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>,
) -> syn::Result<Vec<ParamModel>> {
    let mut params = Vec::new();

    for arg in inputs {
        let FnArg::Typed(pat_type) = arg else {
            // Skip `self` / `&self` / `&mut self`
            continue;
        };

        let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
            return Err(syn::Error::new_spanned(
                &pat_type.pat,
                "expected a simple identifier pattern for method parameter",
            ));
        };

        params.push(ParamModel {
            name: pat_ident.ident.clone(),
            ty: (*pat_type.ty).clone(),
        });
    }

    Ok(params)
}

/// Parse the return type, extracting `T` and `E` from `Result<T, E>`.
///
/// # Errors
///
/// Returns a compile error if the return type is not `Result<T, E>`.
fn parse_return_type(
    ret: &ReturnType,
    method_span: proc_macro2::Span,
) -> syn::Result<(syn::Type, syn::Type)> {
    let ReturnType::Type(_, ty) = ret else {
        return Err(syn::Error::new(
            method_span,
            "service contract methods must return `Result<T, E>`",
        ));
    };

    extract_result_types(ty)
}

/// Given a type that should be `Result<T, E>`, extract `T` and `E`.
fn extract_result_types(ty: &Type) -> syn::Result<(syn::Type, syn::Type)> {
    let Type::Path(type_path) = ty else {
        return Err(syn::Error::new_spanned(
            ty,
            "expected `Result<T, E>` return type",
        ));
    };

    let last_seg = type_path
        .path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new_spanned(ty, "expected `Result<T, E>` return type"))?;

    if last_seg.ident != "Result" {
        return Err(syn::Error::new_spanned(
            ty,
            "expected `Result<T, E>` return type",
        ));
    }

    let syn::PathArguments::AngleBracketed(args) = &last_seg.arguments else {
        return Err(syn::Error::new_spanned(
            ty,
            "expected `Result<T, E>` with generic arguments",
        ));
    };

    let mut iter = args.args.iter();

    let ok_arg = iter
        .next()
        .ok_or_else(|| syn::Error::new_spanned(ty, "Result must have two type arguments"))?;
    let err_arg = iter
        .next()
        .ok_or_else(|| syn::Error::new_spanned(ty, "Result must have two type arguments"))?;

    let syn::GenericArgument::Type(ok_type) = ok_arg else {
        return Err(syn::Error::new_spanned(ok_arg, "expected a type argument"));
    };
    let syn::GenericArgument::Type(err_type) = err_arg else {
        return Err(syn::Error::new_spanned(err_arg, "expected a type argument"));
    };

    Ok((ok_type.clone(), err_type.clone()))
}
