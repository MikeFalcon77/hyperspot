#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use proc_macro::TokenStream;
use syn::parse_macro_input;

mod codegen;
mod contract_error;
mod grpc_contract;
mod grpc_contract_parse;
mod model;
mod parse;
mod projection;
mod proto_bridge;
mod rest_contract;
mod rest_contract_parse;
mod support;

#[proc_macro_attribute]
pub fn contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let contract_attr = parse_macro_input!(attr as parse::ContractAttr);
    let item_trait = parse_macro_input!(item as syn::ItemTrait);

    match parse::parse_trait(contract_attr, &item_trait) {
        Ok(model) => codegen::generate(&model).into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[proc_macro_attribute]
pub fn rest_contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = parse_macro_input!(attr as rest_contract_parse::RestContractAttr);
    let item = parse_macro_input!(item as syn::ItemTrait);

    match rest_contract_parse::parse(attr, item) {
        Ok(model) => rest_contract::generate(&model).into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[proc_macro_attribute]
pub fn grpc_contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = parse_macro_input!(attr as grpc_contract_parse::GrpcContractAttr);
    let item = parse_macro_input!(item as syn::ItemTrait);

    match grpc_contract_parse::parse(attr, item) {
        Ok(model) => grpc_contract::generate(&model).into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[proc_macro_derive(ProtoBridge, attributes(proto_bridge))]
pub fn derive_proto_bridge(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    match proto_bridge::generate(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// `#[derive(ContractError)]` — wire a typed Rust error enum into the
/// PRD #1536 RFC 9457 envelope.
///
/// Per-variant attributes:
/// - `#[error_code("INSUFFICIENT_FUNDS")]` (required)
/// - `#[error_domain("billing.v1")]` (required, or set once on the enum)
/// - `#[canonical(FailedPrecondition)]` (required — one of the 16
///   `ProblemCategory` variants)
///
/// Generates `From<MyError> for Problem` (server-side) and
/// `TryFrom<Problem> for MyError` (client-side); unknown
/// `error_code`/`error_domain` pairs round-trip back as the original
/// `Problem` so callers can still handle them as generic envelopes.
#[proc_macro_derive(
    ContractError,
    attributes(error_code, error_domain, canonical)
)]
pub fn derive_contract_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    match contract_error::generate(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
