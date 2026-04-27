#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use proc_macro::TokenStream;
use syn::parse_macro_input;

mod codegen;
mod model;
mod parse;

#[proc_macro_attribute]
pub fn contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let contract_attr = parse_macro_input!(attr as parse::ContractAttr);
    let item_trait = parse_macro_input!(item as syn::ItemTrait);

    match parse::parse_trait(contract_attr, &item_trait) {
        Ok(model) => codegen::generate(&model).into(),
        Err(err) => err.to_compile_error().into(),
    }
}
