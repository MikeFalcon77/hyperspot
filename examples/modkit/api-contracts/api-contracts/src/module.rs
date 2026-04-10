//! Module definition and wiring for api-contracts.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use modkit::context::ModuleCtx;
use modkit::contracts::Module;
use modkit_contract::ir::validation::{validate_contract, validate_http_binding};
use modkit_contract::policy::{PolicyStack, TracingPolicy};
use modkit_contract::runtime::config::ClientConfig;
use api_contracts_sdk::contract::{PaymentApi, payment_api_ir};
use api_contracts_sdk::rest::payment_api_rest_http_binding;

use crate::client::local::PaymentLocalClient;
use crate::config::ApiContractsConfig;
use crate::domain::service::PaymentDomainService;

/// Module name used to look up an HTTP override in `remote_endpoints`.
const MODULE_NAME: &str = "api-contracts";

/// Service hub demo module — provides [`PaymentApi`].
///
/// Stateless: all per-call state lives in the registered [`Arc<dyn PaymentApi>`]
/// inside the [`modkit::ClientHub`].
pub struct ApiContractsModule;

impl ApiContractsModule {
    /// Construct the module.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ApiContractsModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Module for ApiContractsModule {
    async fn init(&self, ctx: &ModuleCtx) -> anyhow::Result<()> {
        // 1. Validate contract + HTTP binding IR at startup (fail-fast).
        let contract_ir = payment_api_ir();
        let http_binding = payment_api_rest_http_binding();
        validate_contract(&contract_ir)
            .map_err(|errs| anyhow::anyhow!("Contract IR validation failed: {errs:?}"))?;
        validate_http_binding(&contract_ir, &http_binding)
            .map_err(|errs| anyhow::anyhow!("HTTP binding IR validation failed: {errs:?}"))?;

        // 2. Policy stack for the local client.
        let mut policy_stack = PolicyStack::new();
        policy_stack.push(Arc::new(TracingPolicy));
        let policy_stack = Arc::new(policy_stack);

        // 3. Decide transport at init time. Order: gRPC > REST > local.
        let config: ApiContractsConfig = ctx.config_or_default()?;
        let client: Arc<dyn PaymentApi> = if let Some(grpc_url) =
            config.remote_grpc_endpoints.get(MODULE_NAME)
        {
            let cfg = ClientConfig::new(grpc_url.clone());
            Arc::new(
                build_grpc_client(cfg)
                    .await
                    .context("building remote PaymentApi gRPC client")?,
            )
        } else if let Some(base_url) = config.remote_endpoints.get(MODULE_NAME) {
            let cfg = ClientConfig::new(base_url.clone());
            Arc::new(build_remote_client(cfg).context("building remote PaymentApi REST client")?)
        } else {
            let domain_svc = Arc::new(PaymentDomainService::new());
            Arc::new(PaymentLocalClient::new(domain_svc, policy_stack))
        };

        // 4. Register in the global ClientHub.
        ctx.client_hub().register::<dyn PaymentApi>(client);

        tracing::info!("api-contracts initialized");
        Ok(())
    }
}

/// Construct the macro-generated REST client from a [`ClientConfig`].
#[cfg(feature = "rest-client")]
fn build_remote_client(
    config: ClientConfig,
) -> anyhow::Result<api_contracts_sdk::rest::PaymentApiRestClient> {
    Ok(api_contracts_sdk::rest::PaymentApiRestClient::new(
        config,
    ))
}

/// Stub used when `rest-client` feature is disabled — yields a clear error so
/// misconfigured deployments fail at init rather than silently downgrading.
#[cfg(not(feature = "rest-client"))]
fn build_remote_client(
    _config: ClientConfig,
) -> anyhow::Result<crate::client::local::PaymentLocalClient> {
    anyhow::bail!(
        "remote PaymentApi transport requested but the `rest-client` feature is disabled; \
         enable it on `cf-api-contracts`"
    )
}

/// Construct the macro-generated gRPC client from a [`ClientConfig`].
#[cfg(feature = "grpc-client")]
async fn build_grpc_client(
    config: ClientConfig,
) -> anyhow::Result<api_contracts_sdk::grpc::PaymentApiGrpcClient> {
    api_contracts_sdk::grpc::PaymentApiGrpcClient::connect(config)
        .await
        .map_err(|e| anyhow::anyhow!("gRPC channel connect failed: {e}"))
}

#[cfg(not(feature = "grpc-client"))]
async fn build_grpc_client(
    _config: ClientConfig,
) -> anyhow::Result<crate::client::local::PaymentLocalClient> {
    anyhow::bail!(
        "remote PaymentApi gRPC transport requested but the `grpc-client` feature is disabled; \
         enable it on `cf-api-contracts`"
    )
}
