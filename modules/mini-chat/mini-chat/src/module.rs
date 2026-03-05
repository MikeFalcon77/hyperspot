use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use authz_resolver_sdk::AuthZResolverClient;
use mini_chat_sdk::{MiniChatAuditPluginSpecV1, MiniChatModelPolicyPluginSpecV1};
use modkit::api::OpenApiRegistry;
use modkit::contracts::RunnableCapability;
use modkit::{DatabaseCapability, Module, ModuleCtx, RestApiCapability};
use modkit_db::outbox::{Outbox, OutboxHandle, Partitions};
use oagw_sdk::ServiceGatewayClientV1;
use sea_orm_migration::MigrationTrait;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use types_registry_sdk::{RegisterResult, TypesRegistryClient};
use modkit::lifecycle::ReadySignal;
use crate::api::rest::routes;
use crate::config::WorkersConfig;
use crate::domain::ports::{NoopOutbox, WorkersMetricsPort};
use crate::domain::service::{AppServices as GenericAppServices, DbProvider, Repositories};
use crate::infra::leader::{self, LeaderElector};
use crate::infra::outbox::{InfraOutboxEnqueuer, UsageEventHandler};
use crate::infra::workers::metrics::WorkersMetricsMeter;


pub(crate) type AppServices = GenericAppServices<
    TurnRepository,
    MessageRepository,
    QuotaUsageRepository,
    ReactionRepository,
    ChatRepository,
    ThreadSummaryRepository,
>;
use crate::infra::db::repo::attachment_repo::AttachmentRepository;
use crate::infra::db::repo::chat_repo::ChatRepository;
use crate::infra::db::repo::message_repo::MessageRepository;
use crate::infra::db::repo::quota_usage_repo::QuotaUsageRepository;
use crate::infra::db::repo::reaction_repo::ReactionRepository;
use crate::infra::db::repo::thread_summary_repo::ThreadSummaryRepository;
use crate::infra::db::repo::turn_repo::TurnRepository;
use crate::infra::db::repo::vector_store_repo::VectorStoreRepository;
use crate::infra::llm::provider_resolver::ProviderResolver;
use crate::infra::model_policy::ModelPolicyGateway;
use crate::infra::workers::cleanup_worker::CleanupWorker;
use crate::infra::workers::orphan_watchdog::OrphanWatchdog;
use crate::infra::workers::thread_summary_worker::ThreadSummaryWorker;

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
    outbox_handle: Mutex<Option<OutboxHandle>>,
    workers: OnceLock<Arc<Workers>>,
}

impl Default for MiniChatModule {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
            url_prefix: OnceLock::new(),
            outbox_handle: Mutex::new(None),
            workers: OnceLock::new(),
        }
    }
}

#[async_trait]
impl Module for MiniChatModule {
    async fn init(&self, ctx: &ModuleCtx) -> anyhow::Result<()> {
        info!("Initializing {} module", Self::MODULE_NAME);

        let cfg: crate::config::MiniChatConfig = ctx.config_expanded()?;
        cfg.streaming
            .validate()
            .map_err(|e| anyhow::anyhow!("streaming config: {e}"))?;
        cfg.workers
            .validate()
            .map_err(|e| anyhow::anyhow!("workers config: {e}"))?;

        cfg.estimation_budgets
            .validate()
            .map_err(|e| anyhow::anyhow!("estimation_budgets config: {e}"))?;
        cfg.quota
            .validate()
            .map_err(|e| anyhow::anyhow!("quota config: {e}"))?;
        cfg.outbox
            .validate()
            .map_err(|e| anyhow::anyhow!("outbox config: {e}"))?;
        cfg.context
            .validate()
            .map_err(|e| anyhow::anyhow!("context config: {e}"))?;
        for (id, entry) in &cfg.providers {
            entry
                .validate(id)
                .map_err(|e| anyhow::anyhow!("providers config: {e}"))?;
        }

        let vendor = cfg.vendor.trim().to_owned();
        if vendor.is_empty() {
            return Err(anyhow::anyhow!(
                "{}: vendor must be a non-empty string",
                Self::MODULE_NAME
            ));
        }

        let registry = ctx.client_hub().get::<dyn TypesRegistryClient>()?;
        register_plugin_schemas(
            &*registry,
            &[
                (
                    MiniChatModelPolicyPluginSpecV1::gts_schema_with_refs_as_string(),
                    MiniChatModelPolicyPluginSpecV1::gts_schema_id(),
                    "model-policy",
                ),
                (
                    MiniChatAuditPluginSpecV1::gts_schema_with_refs_as_string(),
                    MiniChatAuditPluginSpecV1::gts_schema_id(),
                    "audit",
                ),
            ],
        )
        .await?;

        self.url_prefix
            .set(cfg.url_prefix)
            .map_err(|_| anyhow::anyhow!("{} url_prefix already set", Self::MODULE_NAME))?;

        let db_provider = ctx.db_required()?;
        let db = Arc::new(db_provider);

        // Create the model-policy gateway early for both outbox handler and services.
        let model_policy_gw = Arc::new(ModelPolicyGateway::new(ctx.client_hub(), vendor));

        // Start the outbox pipeline eagerly in init() (migrations ran in phase 2, DB is ready).
        // The framework guarantees stop() is called on init failure, so the pipeline
        // will be shut down cleanly if any later init step errors.
        // The handler resolves the plugin lazily on first message delivery,
        // avoiding a hard dependency on plugin availability during init().
        let outbox_db = db.db();
        let num_partitions = cfg.outbox.num_partitions;
        let queue_name = cfg.outbox.queue_name.clone();

        let outbox_handle =
            Outbox::builder(outbox_db)
                .queue(
                    &queue_name,
                    Partitions::of(u16::try_from(num_partitions).map_err(|_| {
                        anyhow::anyhow!("num_partitions {num_partitions} exceeds u16")
                    })?),
                )
                .decoupled(UsageEventHandler {
                    plugin_provider: model_policy_gw.clone(),
                })
                .start()
                .await
                .map_err(|e| anyhow::anyhow!("outbox start: {e}"))?;

        let outbox = Arc::clone(outbox_handle.outbox());
        let outbox_enqueuer =
            Arc::new(InfraOutboxEnqueuer::new(outbox, queue_name, num_partitions));

        {
            let mut guard = self
                .outbox_handle
                .lock()
                .map_err(|e| anyhow::anyhow!("outbox_handle lock: {e}"))?;
            if guard.is_some() {
                return Err(anyhow::anyhow!(
                    "{} outbox_handle already set",
                    Self::MODULE_NAME
                ));
            }
            *guard = Some(outbox_handle);
        }

        info!("Outbox pipeline started");

        let authz = ctx
            .client_hub()
            .get::<dyn AuthZResolverClient>()
            .map_err(|e| anyhow::anyhow!("failed to get AuthZ resolver: {e}"))?;

        let gateway = ctx
            .client_hub()
            .get::<dyn ServiceGatewayClientV1>()
            .map_err(|e| anyhow::anyhow!("failed to get OAGW gateway: {e}"))?;

        // Register OAGW upstreams for each configured provider.
        crate::infra::oagw_provisioning::register_oagw_upstreams(&gateway, &cfg.providers).await?;

        let provider_resolver = Arc::new(ProviderResolver::new(&gateway, cfg.providers));

        let repos = Repositories {
            chat: Arc::new(ChatRepository::new(modkit_db::odata::LimitCfg {
                default: 20,
                max: 100,
            })),
            attachment: Arc::new(AttachmentRepository),
            message: Arc::new(MessageRepository::new(modkit_db::odata::LimitCfg {
                default: 20,
                max: 100,
            })),
            quota: Arc::new(QuotaUsageRepository),
            turn: Arc::new(TurnRepository),
            reaction: Arc::new(ReactionRepository),
            thread_summary: Arc::new(ThreadSummaryRepository),
            vector_store: Arc::new(VectorStoreRepository),
        };

        // Clone Arcs needed by Workers before AppServices consumes them.
        let db_for_workers = Arc::clone(&db);
        let turn_repo_for_workers = Arc::clone(&repos.turn);
        let chat_repo_for_workers = Arc::clone(&repos.chat);
        let message_repo_for_workers = Arc::clone(&repos.message);
        let provider_resolver_for_workers = Arc::clone(&provider_resolver);
        let workers_config = cfg.workers.clone();

        let services = Arc::new(AppServices::new(
            &repos,
            db,
            authz,
            &(model_policy_gw.clone() as Arc<dyn crate::domain::repos::ModelResolver>),
            provider_resolver,
            cfg.streaming,
            model_policy_gw.clone() as Arc<dyn crate::domain::repos::PolicySnapshotProvider>,
            model_policy_gw as Arc<dyn crate::domain::repos::UserLimitsProvider>,
            cfg.estimation_budgets,
            cfg.quota,
            outbox_enqueuer,
            cfg.context,
        ));

        self.service
            .set(services)
            .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;

        // Build workers bundle (leader elector + config + worker instances)
        let workers = Arc::new(
            Workers::new(
                db_for_workers,
                turn_repo_for_workers,
                chat_repo_for_workers,
                message_repo_for_workers,
                provider_resolver_for_workers,
                workers_config,
            )
            .await?,
        );
        self.workers
            .set(workers)
            .map_err(|_| anyhow::anyhow!("{} workers already set", Self::MODULE_NAME))?;

        info!("{} module initialized successfully", Self::MODULE_NAME);
        Ok(())
    }
}

impl MiniChatModule {
    /// Lifecycle entry point — spawns all enabled background workers.
    ///
    /// Each worker is wrapped in leader election and runs until the
    /// provided `cancel` token fires (module shutdown).
    #[allow(clippy::cognitive_complexity)]
    pub(crate) async fn run_workers(
        self: Arc<Self>,
        cancel: CancellationToken,
        ready: ReadySignal,
    ) -> anyhow::Result<()> {
        let workers = self
            .workers
            .get()
            .ok_or_else(|| anyhow::anyhow!("run_workers: workers not initialized"))?;

        let handles = workers.spawn_all(&cancel);
        ready.notify(); // Starting -> Running

        if handles.is_empty() {
            info!("no workers enabled, waiting for shutdown");
            cancel.cancelled().await;
            return Ok(());
        }

        info!(count = handles.len(), "background workers running");

        // Wait for shutdown then join worker tasks.
        cancel.cancelled().await;
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "worker exited with error"),
                Err(e) => warn!(error = %e, "worker task panicked"),
            }
        }

        info!("all background workers stopped");
        Ok(())
    }
}

/// Bundle of background workers + their dependencies.
struct Workers {
    leader: Arc<dyn LeaderElector>,
    config: WorkersConfig,
    orphan_watchdog: Arc<OrphanWatchdog<TurnRepository>>,
    thread_summary: Arc<ThreadSummaryWorker<ChatRepository, MessageRepository>>,
    cleanup: Arc<CleanupWorker>,
}

impl Workers {
    #[allow(clippy::unused_async)]
    async fn new(
        db: Arc<DbProvider>,
        turn_repo: Arc<TurnRepository>,
        chat_repo: Arc<ChatRepository>,
        message_repo: Arc<MessageRepository>,
        provider_resolver: Arc<crate::infra::llm::provider_resolver::ProviderResolver>,
        config: WorkersConfig,
    ) -> anyhow::Result<Self> {
        let meter = opentelemetry::global::meter("mini-chat");
        let metrics: Arc<dyn WorkersMetricsPort> = Arc::new(WorkersMetricsMeter::new(&meter));
        let outbox = Arc::new(NoopOutbox);

        let leader: Arc<dyn LeaderElector> = {
            #[cfg(feature = "k8s-leader")]
            {
                use crate::infra::leader::k8s_lease::{K8sLeaseConfig, K8sLeaseElector};

                let in_k8s = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();
                if in_k8s {
                    let namespace = std::env::var("POD_NAMESPACE")
                        .map_err(|_| anyhow::anyhow!("POD_NAMESPACE is required in k8s"))?;
                    let identity =
                        std::env::var("POD_NAME").map_err(|_| anyhow::anyhow!("POD_NAME is required in k8s"))?;

                    let cfg = K8sLeaseConfig {
                        namespace,
                        identity,
                        lease_prefix: config.lease_prefix.clone(),
                        lease_duration: std::time::Duration::from_secs(15),
                        renew_period: std::time::Duration::from_secs(2),
                    };
                    cfg.validate()?;
                    Arc::new(K8sLeaseElector::from_default(cfg).await?)
                } else {
                    leader::noop()
                }
            }
            #[cfg(not(feature = "k8s-leader"))]
            {
                leader::noop()
            }
        };

        let orphan_watchdog = Arc::new(OrphanWatchdog::new(
            Arc::clone(&db),
            turn_repo,
            config.orphan_watchdog,
            Arc::clone(&metrics),
            outbox,
        ));

        let thread_summary_repo = Arc::new(
            crate::infra::db::repo::thread_summary_repo::ThreadSummaryRepository,
        );
        let thread_summary = Arc::new(ThreadSummaryWorker::new(
            Arc::clone(&db),
            config.thread_summary.clone(),
            Arc::clone(&metrics),
            provider_resolver,
            chat_repo,
            message_repo,
            thread_summary_repo,
        ));

        let cleanup = Arc::new(CleanupWorker::new(
            db,
            config.cleanup,
            metrics,
        ));

        Ok(Self {
            leader,
            config,
            orphan_watchdog,
            thread_summary,
            cleanup,
        })
    }

    #[allow(clippy::cognitive_complexity)]
    fn spawn_all(
        &self,
        cancel: &CancellationToken,
    ) -> Vec<tokio::task::JoinHandle<anyhow::Result<()>>> {
        let mut handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

        // ── Orphan watchdog ──
        if self.config.orphan_watchdog.enabled {
            let watchdog = Arc::clone(&self.orphan_watchdog);
            let leader = Arc::clone(&self.leader);
            let child = cancel.child_token();
            handles.push(tokio::spawn(async move {
                leader
                    .run_role(
                        "orphan-watchdog-leader",
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

        // ── Thread summary worker ──
        if self.config.thread_summary.enabled {
            let worker = Arc::clone(&self.thread_summary);
            let leader = Arc::clone(&self.leader);
            let child = cancel.child_token();
            handles.push(tokio::spawn(async move {
                leader
                    .run_role(
                        "thread-summary-leader",
                        child,
                        leader::work_fn(move |c| {
                            let w = Arc::clone(&worker);
                            async move { w.run(c).await }
                        }),
                    )
                    .await
            }));
            info!("thread summary worker spawned");
        }

        // ── Cleanup worker ──
        if self.config.cleanup.enabled {
            let worker = Arc::clone(&self.cleanup);
            let leader = Arc::clone(&self.leader);
            let child = cancel.child_token();
            handles.push(tokio::spawn(async move {
                leader
                    .run_role(
                        "cleanup-leader",
                        child,
                        leader::work_fn(move |c| {
                            let w = Arc::clone(&worker);
                            async move { w.run(c).await }
                        }),
                    )
                    .await
            }));
            info!("cleanup worker spawned");
        }

        handles
    }
}

impl DatabaseCapability for MiniChatModule {
    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        use sea_orm_migration::MigratorTrait;
        info!("Providing mini-chat database migrations");
        let mut m = crate::infra::db::migrations::Migrator::migrations();
        m.extend(modkit_db::outbox::outbox_migrations());
        m
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

#[async_trait]
impl RunnableCapability for MiniChatModule {
    async fn start(&self, _cancel: CancellationToken) -> anyhow::Result<()> {
        // Outbox pipeline already started in init().
        Ok(())
    }

    async fn stop(&self, cancel: CancellationToken) -> anyhow::Result<()> {
        let handle = self
            .outbox_handle
            .lock()
            .map_err(|e| anyhow::anyhow!("outbox_handle lock: {e}"))?
            .take();
        if let Some(handle) = handle {
            info!("Stopping outbox pipeline");
            tokio::select! {
                () = handle.stop() => {
                    info!("Outbox pipeline stopped");
                }
                () = cancel.cancelled() => {
                    info!("Outbox pipeline stop cancelled by framework deadline");
                }
            }
        }
        Ok(())
    }
}

async fn register_plugin_schemas(
    registry: &dyn TypesRegistryClient,
    schemas: &[(String, &str, &str)],
) -> anyhow::Result<()> {
    let mut payload = Vec::with_capacity(schemas.len());
    for (schema_str, schema_id, _label) in schemas {
        let mut schema_json: serde_json::Value = serde_json::from_str(schema_str)?;
        let obj = schema_json
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("schema {schema_id} is not a JSON object"))?;
        obj.insert(
            "additionalProperties".to_owned(),
            serde_json::Value::Bool(false),
        );
        payload.push(schema_json);
    }
    let results = registry.register(payload).await?;
    RegisterResult::ensure_all_ok(&results)?;
    for (_schema_str, schema_id, label) in schemas {
        info!(schema_id = %schema_id, "Registered {label} plugin schema in types-registry");
    }
    Ok(())
}
