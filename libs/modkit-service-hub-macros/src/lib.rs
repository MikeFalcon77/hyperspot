#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Proc macros for `modkit-service-hub`.
//!
//! Provides the `#[service_contract]` attribute macro that eliminates
//! manual Contract IR / `ServiceDescriptor` boilerplate.
//!
//! # Usage
//!
//! ```rust,ignore
//! use modkit_service_hub::service_contract;
//!
//! #[service_contract(module = "billing", version = "v1")]
//! pub trait PaymentService: Send + Sync {
//!     #[idempotency(NonIdempotentWrite)]
//!     async fn charge(&self, ctx: SecurityContext, req: ChargeRequest)
//!         -> Result<ChargeResponse, CanonicalError>;
//! }
//! ```

use proc_macro::TokenStream;
use syn::parse_macro_input;

mod codegen;
mod model;
mod parse;

/// Attribute macro that generates a service contract from a Rust trait.
///
/// Generates:
/// - The trait itself annotated with `#[async_trait]`
/// - A static `ServiceDescriptor` for zero-allocation runtime metadata
/// - An IR builder function for validation and codegen
/// - A `ServiceContract` impl for `dyn TraitName`
///
/// # Attribute parameters
///
/// - `module = "..."` -- required, the module name
/// - `version = "..."` -- required, the API version
///
/// # Method attributes
///
/// - `#[idempotency(SafeRead)]` / `#[idempotency(IdempotentWrite)]` /
///   `#[idempotency(NonIdempotentWrite)]` -- optional, defaults to `NonIdempotentWrite`
/// - `#[streaming]` -- marks the method as server-streaming; the return type
///   is rewritten to `Pin<Box<dyn Stream<Item = Result<T, E>> + Send + 'static>>`
///
/// # Errors
///
/// Produces compile errors for:
/// - Missing `module` or `version` in attribute
/// - Method not returning `Result<T, E>`
/// - `#[streaming]` on an `async fn`
/// - Unknown `#[idempotency(...)]` variant
#[proc_macro_attribute]
pub fn service_contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    let contract_attr = parse_macro_input!(attr as parse::ContractAttr);
    let item_trait = parse_macro_input!(item as syn::ItemTrait);

    match parse::parse_trait(contract_attr, &item_trait) {
        Ok(model) => codegen::generate(&model).into(),
        Err(err) => err.to_compile_error().into(),
    }
}
