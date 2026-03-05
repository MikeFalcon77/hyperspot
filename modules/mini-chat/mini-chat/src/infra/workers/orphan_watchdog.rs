//! Orphan watchdog — detects and finalizes turns abandoned by crashed pods.
//!
//! Periodically scans for `running` turns whose `started_at` exceeds the
//! configured timeout threshold, then CAS-finalizes them to `failed` with
//! `error_code = "orphan_timeout"` using the shared finalization path.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::OrphanWatchdogConfig;
use crate::domain::ports::{OutboxPort, WorkersMetricsPort};
use crate::domain::repos::TurnRepository;
use crate::domain::service::DbProvider;

/// Background worker that detects orphaned turns and transitions them
/// to `failed` with `error_code = "orphan_timeout"`.
#[allow(dead_code)] // Fields used in P2 when scan logic is implemented.
pub struct OrphanWatchdog<TR: TurnRepository> {
    db: Arc<DbProvider>,
    turn_repo: Arc<TR>,
    config: OrphanWatchdogConfig,
    metrics: Arc<dyn WorkersMetricsPort>,
    outbox: Arc<dyn OutboxPort>,
}

impl<TR: TurnRepository + 'static> OrphanWatchdog<TR> {
    #[must_use]
    pub fn new(
        db: Arc<DbProvider>,
        turn_repo: Arc<TR>,
        config: OrphanWatchdogConfig,
        metrics: Arc<dyn WorkersMetricsPort>,
        outbox: Arc<dyn OutboxPort>,
    ) -> Self {
        Self {
            db,
            turn_repo,
            config,
            metrics,
            outbox,
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

        // Run an immediate scan on startup, then tick periodically.
        if let Err(e) = self.scan_and_finalize(timeout, &cancel).await {
            warn!(error = %e, "orphan watchdog initial scan failed");
        }

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    info!("orphan watchdog stopped");
                    return Ok(());
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.scan_and_finalize(timeout, &cancel).await {
                        warn!(error = %e, "orphan watchdog scan failed");
                    }
                }
            }
        }
    }

    // TODO(P2): Implement orphan detection and CAS finalization.
    // Requires:
    //   - TurnRepository::find_orphaned_turns()
    //   - FinalizationService or direct CAS path
    //   - OutboxPort integration
    #[allow(clippy::unused_async)]
    async fn scan_and_finalize(
        &self,
        _timeout: Duration,
        _cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        debug!("orphan scan: no implementation yet (stub)");
        Ok(())
    }
}
