use modkit_db::secure::DBRunner;
use modkit_security::AccessScope;
use serde_json::Value;
use uuid::Uuid;

/// Metrics port for background workers.
///
/// Implementations MUST keep label cardinality low.
pub trait WorkersMetricsPort: Send + Sync {
    fn orphan_turn_total(&self, result: &'static str);
    fn streams_aborted_total(&self, trigger: &'static str);
    fn summary_runs_total(&self, result: &'static str);
    fn cleanup_runs_total(&self, result: &'static str);
}

/// Outbox port (stub for P1 wiring).
///
/// Producers should call this inside the same DB transaction as the side effects.
/// This is a placeholder until `modkit_db::outbox::enqueue` is available.
pub trait OutboxPort: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn enqueue(
        &self,
        runner: &dyn DBRunner,
        scope: &AccessScope,
        namespace: &'static str,
        topic: &'static str,
        tenant_id: Option<Uuid>,
        dedupe_key: Option<String>,
        payload: Value,
    ) -> Result<(), anyhow::Error>;
}

