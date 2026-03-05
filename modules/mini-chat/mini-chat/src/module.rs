use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use authz_resolver_sdk::AuthZResolverClient;
use mini_chat_sdk::MiniChatModelPolicyPluginSpecV1;
use modkit::api::OpenApiRegistry;
use modkit::{DatabaseCapability, Module, ModuleCtx, RestApiCapability};
use oagw_sdk::ServiceGatewayClientV1;
use sea_orm_migration::MigrationTrait;
use tracing::info;
use types_registry_sdk::{RegisterResult, TypesRegistryClient};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use modkit::lifecycle::ReadySignal;
use crate::api::rest::routes;
use crate::config::WorkersConfig;
use crate::domain::service::{AppServices as GenericAppServices, DbProvider, Repositories};
use crate::infra::leader::{self, LeaderElector};

pub(crate) type AppServices =
    GenericAppServices<TurnRepository, MessageRepository, QuotaUsageRepository, ChatRepository>;
use crate::infra::db::repo::attachment_repo::AttachmentRepository;
use crate::infra::db::repo::chat_repo::ChatRepository;
use crate::infra::db::repo::message_repo::MessageRepository;
use crate::infra::db::repo::model_pref_repo::ModelPrefRepository;
use crate::infra::db::repo::quota_usage_repo::QuotaUsageRepository;
use crate::infra::db::repo::reaction_repo::ReactionRepository;
use crate::infra::db::repo::thread_summary_repo::ThreadSummaryRepository;
use crate::infra::db::repo::turn_repo::TurnRepository;
use crate::infra::db::repo::vector_store_repo::VectorStoreRepository;
use crate::infra::llm::providers::{ProviderConfig, ProviderKind, create_provider};
use crate::infra::model_policy::ModelPolicyGateway;
use crate::infra::workers::orphan_watchdog::OrphanWatchdog;

/// Default URL prefix for all mini-chat REST routes.
pub const DEFAULT_URL_PREFIX: &str = "/mini-chat";

/// The mini-chat module: multi-tenant AI chat with SSE streaming.
#[modkit::module(
    name = "mini-chat",
    deps = ["types-registry", "authz-resolver", "oagw"],
    capabilities = [db, rest, stateful],
    lifecycle(entry = "run_workers", stop_timeout = "30s", await_ready),
)]
pub struct MiniChatModule {
    service: OnceLock<Arc<AppServices>>,
    url_prefix: OnceLock<String>,

    // Worker dependencies (populated during init, consumed by run_workers)
    db: OnceLock<Arc<DbProvider>>,
    turn_repo: OnceLock<Arc<TurnRepository>>,
    leader_elector: OnceLock<Arc<dyn LeaderElector>>,
    workers_config: OnceLock<WorkersConfig>,
}

impl Default for MiniChatModule {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
            url_prefix: OnceLock::new(),
            db: OnceLock::new(),
            turn_repo: OnceLock::new(),
            leader_elector: OnceLock::new(),
            workers_config: OnceLock::new(),
        }
    }
}

#[async_trait]
impl Module for MiniChatModule {
    #[allow(clippy::cognitive_complexity)]
    async fn init(&self, ctx: &ModuleCtx) -> anyhow::Result<()> {
        info!("Initializing {} module", Self::MODULE_NAME);

        let cfg: crate::config::MiniChatConfig = ctx.config()?;
        cfg.streaming
            .validate()
            .map_err(|e| anyhow::anyhow!("streaming config: {e}"))?;
        cfg.workers
            .validate()
            .map_err(|e| anyhow::anyhow!("workers config: {e}"))?;

        let vendor = cfg.vendor.trim().to_owned();
        if vendor.is_empty() {
            return Err(anyhow::anyhow!(
                "{}: vendor must be a non-empty string",
                Self::MODULE_NAME
            ));
        }

        // Register model-policy plugin schema in types-registry
        let registry = ctx.client_hub().get::<dyn TypesRegistryClient>()?;
        let schema_str = MiniChatModelPolicyPluginSpecV1::gts_schema_with_refs_as_string();
        let mut schema_json: serde_json::Value = serde_json::from_str(&schema_str)?;
        if let Some(obj) = schema_json.as_object_mut() {
            obj.insert(
                "additionalProperties".to_owned(),
                serde_json::Value::Bool(false),
            );
        }
        let results = registry.register(vec![schema_json]).await?;
        RegisterResult::ensure_all_ok(&results)?;
        info!(
            schema_id = %MiniChatModelPolicyPluginSpecV1::gts_schema_id(),
            "Registered model-policy plugin schema in types-registry"
        );

        self.url_prefix
            .set(cfg.url_prefix)
            .map_err(|_| anyhow::anyhow!("{} url_prefix already set", Self::MODULE_NAME))?;

        let db = Arc::new(ctx.db_required()?);

        let authz = ctx
            .client_hub()
            .get::<dyn AuthZResolverClient>()
            .map_err(|e| anyhow::anyhow!("failed to get AuthZ resolver: {e}"))?;

        let gateway = ctx
            .client_hub()
            .get::<dyn ServiceGatewayClientV1>()
            .map_err(|e| anyhow::anyhow!("failed to get OAGW gateway: {e}"))?;

        // TODO: provider kind and upstream alias should come from config in a
        // follow-up — hardcoded to OpenAI Responses for initial P1 wiring.
        let llm = create_provider(
            gateway,
            ProviderConfig {
                kind: ProviderKind::OpenAiResponses,
                upstream_alias: "openai".to_owned(),
            },
        );

        let repos = Repositories {
            chat: Arc::new(ChatRepository::new(modkit_db::odata::LimitCfg {
                default: 20,
                max: 100,
            })),
            attachment: Arc::new(AttachmentRepository),
            message: Arc::new(MessageRepository),
            quota: Arc::new(QuotaUsageRepository),
            turn: Arc::new(TurnRepository),
            reaction: Arc::new(ReactionRepository),
            model_pref: Arc::new(ModelPrefRepository),
            thread_summary: Arc::new(ThreadSummaryRepository),
            vector_store: Arc::new(VectorStoreRepository),
        };

        let model_policy_gw = Arc::new(ModelPolicyGateway::new(ctx.client_hub(), vendor));
        let services = Arc::new(AppServices::new(
            &repos,
            db,
            authz,
            model_policy_gw,
            llm,
            cfg.streaming,
        ));

        self.service
            .set(services)
            .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;

        // Store worker dependencies
        let _r = self.leader_elector.set(leader::noop());
        let _r = self.workers_config.set(cfg.workers);

        info!("{} module initialized successfully", Self::MODULE_NAME);
        Ok(())
    }
}

impl MiniChatModule {
    /// Lifecycle entry point — spawns all enabled background workers.
    ///
    /// Each worker is wrapped in leader election and runs until the
    /// provided `cancel` token fires (module shutdown).
    pub(crate) async fn run_workers(
        self: Arc<Self>,
        cancel: CancellationToken,
        ready: ReadySignal,
    ) -> anyhow::Result<()> {
        tracing::info!("HTTP server bound on {}", addr);
        ready.notify(); // Starting -> Running

        // Graceful shutdown on cancel
        let shutdown = {
            let cancel = cancel.clone();
            async move {
                cancel.cancelled().await;
                tracing::info!("HTTP server shutting down gracefully (cancellation)");
            }
        };

        let mut handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

        // ── Orphan watchdog ──
        if config.orphan_watchdog.enabled {
            let watchdog = Arc::new(OrphanWatchdog::new(
                Arc::clone(db),
                Arc::clone(turn_repo),
                config.orphan_watchdog,
            ));
            let leader = Arc::clone(leader);
            let child = cancel.child_token();
            handles.push(tokio::spawn(async move {
                leader
                    .run_role(
                        "mini-chat-orphan-watchdog",
                        child,
                        leader::work_fn(move |c| {
                            let w = Arc::clone(&watchdog);
                            async move { w.run(c).await }
                        }),
                    )
                    .await
            }));
            info!("orphan watchdog worker spawned");
        }

        // ── Thread summary worker (stub — TODO: implement in next phase) ──
        if config.thread_summary.enabled {
            info!("thread summary worker enabled (not yet implemented)");
        }

        // ── Cleanup worker (stub — TODO: implement in next phase) ──
        if config.cleanup.enabled {
            info!("cleanup worker enabled (not yet implemented)");
        }

        if handles.is_empty() {
            info!("no workers enabled, waiting for shutdown");
            cancel.cancelled().await;
            return Ok(());
        }

        info!(count = handles.len(), "background workers running");

        // Workers run until cancel fires, then we join them
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "worker exited with error"),
                Err(e) => warn!(error = %e, "worker task panicked"),
            }
        }

        info!("all background workers stopped");


        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|e| anyhow::anyhow!(e))

        Ok()
    }
}

impl DatabaseCapability for MiniChatModule {
    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        use sea_orm_migration::MigratorTrait;
        info!("Providing mini-chat database migrations");
        crate::infra::db::migrations::Migrator::migrations()
    }
}

impl RestApiCapability for MiniChatModule {
    fn register_rest(
        &self,
        _ctx: &ModuleCtx,
        router: axum::Router,
        openapi: &dyn OpenApiRegistry,
    ) -> anyhow::Result<axum::Router> {
        let services = self
            .service
            .get()
            .ok_or_else(|| anyhow::anyhow!("{} not initialized", Self::MODULE_NAME))?;

        info!("Registering mini-chat REST routes");
        let prefix = self
            .url_prefix
            .get()
            .ok_or_else(|| anyhow::anyhow!("{} not initialized (url_prefix)", Self::MODULE_NAME))?;

        let router = routes::register_routes(router, openapi, Arc::clone(services), prefix);
        info!("Mini-chat REST routes registered successfully");
        Ok(router)
    }
}
