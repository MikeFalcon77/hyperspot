use syn::spanned::Spanned;
use syn::{FnArg, ItemTrait, Meta, Pat, ReturnType, TraitItem, TraitItemFn, Type};

use crate::model::{ContractModel, Idempotency, MethodKind, MethodModel, ParamModel};

pub struct ContractAttr {
    pub module: String,
    pub version: String,
}

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

pub fn parse_trait(attr: ContractAttr, item: &ItemTrait) -> syn::Result<ContractModel> {
    let mut methods = Vec::new();

    for trait_item in &item.items {
        let TraitItem::Fn(method) = trait_item else {
            continue;
        };
        methods.push(parse_method(method)?);
    }

    let attrs = item.attrs.clone();

    Ok(ContractModel {
        module: attr.module,
        version: attr.version,
        trait_name: item.ident.clone(),
        vis: item.vis.clone(),
        supertraits: item.supertraits.clone(),
        methods,
        attrs,
    })
}

fn parse_method(method: &TraitItemFn) -> syn::Result<MethodModel> {
    let sig = &method.sig;
    let name = sig.ident.clone();

    let is_streaming = has_attr(&method.attrs, "streaming");
    let idempotency = parse_idempotency(&method.attrs)?;

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

    let params = parse_params(&sig.inputs)?;
    let (output_type, error_type) = parse_return_type(&sig.output, sig.ident.span())?;
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

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn is_macro_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("streaming") || attr.path().is_ident("idempotency")
}

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
                    "unknown idempotency variant `{other}`; expected SafeRead, IdempotentWrite, or NonIdempotentWrite"
                ),
            )),
        };
    }

    Ok(Idempotency::NonIdempotentWrite)
}

fn parse_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>,
) -> syn::Result<Vec<ParamModel>> {
    let mut params = Vec::new();

    for arg in inputs {
        let FnArg::Typed(pat_type) = arg else {
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

fn parse_return_type(
    ret: &ReturnType,
    method_span: proc_macro2::Span,
) -> syn::Result<(syn::Type, syn::Type)> {
    let ReturnType::Type(_, ty) = ret else {
        return Err(syn::Error::new(
            method_span,
            "contract methods must return `Result<T, E>`",
        ));
    };

    extract_result_types(ty)
}

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
