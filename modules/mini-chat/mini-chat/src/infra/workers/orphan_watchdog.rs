//! Orphan watchdog — detects and finalizes turns abandoned by crashed pods.
//!
//! Periodically scans for `running` turns whose `started_at` exceeds the
//! configured timeout threshold, then CAS-finalizes them to `failed` with
//! `error_code = "orphan_timeout"` using the shared finalization path.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use modkit_security::AccessScope;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::OrphanWatchdogConfig;
use crate::domain::repos::TurnRepository;
use crate::domain::service::finalize;
use crate::domain::service::DbProvider;
use crate::infra::db::entity::chat_turn::TurnState;

/// Background worker that detects orphaned turns and transitions them
/// to `failed` with `error_code = "orphan_timeout"`.
pub struct OrphanWatchdog<TR: TurnRepository> {
    db: Arc<DbProvider>,
    turn_repo: Arc<TR>,
    config: OrphanWatchdogConfig,
}

impl<TR: TurnRepository + 'static> OrphanWatchdog<TR> {
    #[must_use]
    pub fn new(db: Arc<DbProvider>, turn_repo: Arc<TR>, config: OrphanWatchdogConfig) -> Self {
        Self {
            db,
            turn_repo,
            config,
        }
    }

    /// Main worker loop. Runs until `cancel` fires.
    ///
    /// # Errors
    ///
    /// Returns only on cancellation (Ok) or if a fatal infrastructure
    /// error prevents the worker from continuing.
    #[allow(clippy::cognitive_complexity)]
    pub async fn run(&self, cancel: CancellationToken) -> anyhow::Result<()> {
        let interval = Duration::from_secs(u64::from(self.config.scan_interval_secs));
        let timeout = Duration::from_secs(u64::from(self.config.timeout_threshold_secs));

        info!(
            scan_interval_secs = self.config.scan_interval_secs,
            timeout_secs = self.config.timeout_threshold_secs,
            "orphan watchdog started"
        );

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    info!("orphan watchdog stopped");
                    return Ok(());
                }
                () = tokio::time::sleep(interval) => {
                    if let Err(e) = self.scan_and_finalize(timeout).await {
                        warn!(error = %e, "orphan watchdog scan failed");
                    }
                }
            }
        }
    }

    #[allow(clippy::cognitive_complexity)]
    async fn scan_and_finalize(&self, timeout: Duration) -> anyhow::Result<()> {
        let conn = self.db.conn().context("orphan watchdog: DB connection")?;
        let scope = AccessScope::allow_all();

        let orphans = self
            .turn_repo
            .find_orphaned_turns(&conn, &scope, timeout)
            .await
            .context("find orphaned turns")?;

        if orphans.is_empty() {
            debug!("orphan scan: no orphaned turns found");
            return Ok(());
        }

        info!(count = orphans.len(), "orphan scan: found orphaned turns");

        let mut finalized = 0u32;
        for turn in &orphans {
            let tenant_scope = AccessScope::for_tenant(turn.tenant_id);
            match finalize::cas_finalize_terminal(
                &*self.turn_repo,
                &conn,
                &tenant_scope,
                turn.id,
                TurnState::Failed,
                Some("orphan_timeout".to_owned()),
                None,
            )
            .await
            {
                Ok(true) => {
                    info!(
                        turn_id = %turn.id,
                        chat_id = %turn.chat_id,
                        tenant_id = %turn.tenant_id,
                        "orphan turn finalized"
                    );
                    finalized += 1;
                }
                Ok(false) => {
                    debug!(
                        turn_id = %turn.id,
                        "orphan turn already finalized by another path"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        turn_id = %turn.id,
                        "failed to finalize orphan turn"
                    );
                }
            }
        }

        if finalized > 0 {
            info!(finalized, total = orphans.len(), "orphan scan complete");
        }

        Ok(())
    }
}
