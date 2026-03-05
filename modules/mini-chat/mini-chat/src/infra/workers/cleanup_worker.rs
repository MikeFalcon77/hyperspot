//! Cleanup worker — removes provider resources for soft-deleted chats.
//!
//! Periodically scans for soft-deleted chats that still have provider
//! resources (vector stores, files) and invokes OAGW to delete them.
//!
//! - `not_found` / `already_deleted` responses from the provider are treated
//!   as success (idempotent).
//! - Partial failures are recorded per attachment (`cleanup_attempts`,
//!   `last_cleanup_error`), retried with exponential backoff up to
//!   `max_attempts`.
//! - A chat is considered fully cleaned up only when all its attachments
//!   have been removed or permanently failed.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use modkit_security::AccessScope;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::CleanupConfig;
use crate::domain::ports::WorkersMetricsPort;
use crate::domain::service::DbProvider;

/// Background worker that cleans up provider resources for soft-deleted chats.
pub struct CleanupWorker {
    db: Arc<DbProvider>,
    config: CleanupConfig,
    metrics: Arc<dyn WorkersMetricsPort>,
}

impl CleanupWorker {
    #[must_use]
    pub fn new(
        db: Arc<DbProvider>,
        config: CleanupConfig,
        metrics: Arc<dyn WorkersMetricsPort>,
    ) -> Self {
        Self {
            db,
            config,
            metrics,
        }
    }

    /// Main worker loop. Runs until `cancel` fires.
    ///
    /// # Errors
    ///
    /// Returns only on cancellation (`Ok`) or fatal infrastructure failure.
    #[allow(clippy::cognitive_complexity)]
    pub async fn run(&self, cancel: CancellationToken) -> anyhow::Result<()> {
        let interval = Duration::from_secs(u64::from(self.config.scan_interval_secs));

        info!(
            scan_interval_secs = self.config.scan_interval_secs,
            max_attempts = self.config.max_attempts,
            base_delay_secs = self.config.base_delay_secs,
            "cleanup worker started"
        );

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    info!("cleanup worker stopped");
                    return Ok(());
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.scan_and_cleanup(&cancel).await {
                        warn!(error = %e, "cleanup scan failed");
                    }
                }
            }
        }
    }

    #[allow(clippy::cognitive_complexity, clippy::unused_async)]
    async fn scan_and_cleanup(&self, cancel: &CancellationToken) -> anyhow::Result<()> {
        let _conn = self.db.conn().context("cleanup worker: DB connection")?;
        let _scope = AccessScope::allow_all();

        // TODO(P1): Implement the full scan + cleanup flow:
        //
        // 1. Query soft-deleted chats that still have provider resources
        //    pending cleanup. Requires:
        //      - ChatRepository::find_pending_cleanup() — chats where
        //        deleted_at IS NOT NULL and has attachments with
        //        cleanup_attempts < max_attempts
        //
        // 2. For each chat (with cancellation check):
        //    a. Load attachments that still need cleanup
        //    b. For each attachment:
        //       - Call OAGW to delete the vector store / file
        //       - On success (or 404/already-deleted): mark attachment cleaned
        //       - On failure: increment cleanup_attempts, record last_cleanup_error,
        //         apply exponential backoff (base_delay_secs * 2^attempt)
        //       - Emit cleanup_runs_total("success") or cleanup_runs_total("error")
        //    c. If all attachments cleaned, mark chat as fully cleaned
        //
        // Dependencies not yet available:
        //   - ChatRepository::find_pending_cleanup()
        //   - AttachmentRepository methods (find_by_chat, mark_cleaned,
        //     increment_cleanup_attempts)
        //   - OAGW cleanup client (delete vector store / file)
        //   - Attachment cleanup tracking columns (cleanup_attempts,
        //     last_cleanup_error, cleaned_at)

        if cancel.is_cancelled() {
            return Ok(());
        }

        debug!("cleanup scan: no implementation yet (stub)");
        Ok(())
    }
}
