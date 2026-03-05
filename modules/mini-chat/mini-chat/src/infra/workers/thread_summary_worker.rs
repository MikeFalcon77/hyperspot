//! Thread summary worker — compresses chat history via LLM summarization.
//!
//! Periodically scans for chats that need summarization based on:
//! - message count exceeding a threshold (default: 20)
//! - user turn count exceeding a threshold (default: every 15 turns)
//!
//! For each qualifying chat, the worker loads the previous summary + recent
//! messages, calls the LLM for summarization (`requester_type=system`), saves
//! the new summary, and marks processed messages as `is_compressed = true`.
//!
//! On failure the previous summary is kept and messages are NOT marked
//! archived, ensuring safe retry on the next scan.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::ThreadSummaryConfig;
use crate::domain::ports::WorkersMetricsPort;
use crate::domain::repos::{ChatRepository, MessageRepository};
use crate::domain::service::DbProvider;
use crate::infra::llm::provider_resolver::ProviderResolver;

/// Background worker that compresses chat history via LLM summarization.
#[allow(dead_code)] // Fields used in P3 when scan logic is implemented.
pub struct ThreadSummaryWorker<CR: ChatRepository, MR: MessageRepository> {
    db: Arc<DbProvider>,
    config: ThreadSummaryConfig,
    metrics: Arc<dyn WorkersMetricsPort>,
    provider_resolver: Arc<ProviderResolver>,
    chat_repo: Arc<CR>,
    message_repo: Arc<MR>,
    thread_summary_repo: Arc<crate::infra::db::repo::thread_summary_repo::ThreadSummaryRepository>,
}

impl<CR: ChatRepository + 'static, MR: MessageRepository + 'static> ThreadSummaryWorker<CR, MR> {
    #[must_use]
    pub fn new(
        db: Arc<DbProvider>,
        config: ThreadSummaryConfig,
        metrics: Arc<dyn WorkersMetricsPort>,
        provider_resolver: Arc<ProviderResolver>,
        chat_repo: Arc<CR>,
        message_repo: Arc<MR>,
        thread_summary_repo: Arc<
            crate::infra::db::repo::thread_summary_repo::ThreadSummaryRepository,
        >,
    ) -> Self {
        Self {
            db,
            config,
            metrics,
            provider_resolver,
            chat_repo,
            message_repo,
            thread_summary_repo,
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
            msg_count_threshold = self.config.msg_count_threshold,
            turn_threshold = self.config.turn_threshold,
            summary_model = %if self.config.summary_model.is_empty() { "<chat model>" } else { &self.config.summary_model },
            "thread summary worker started"
        );

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    info!("thread summary worker stopped");
                    return Ok(());
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.scan_and_summarize(&cancel).await {
                        warn!(error = %e, "thread summary scan failed");
                    }
                }
            }
        }
    }

    // TODO(P3): Implement thread summary scan and LLM summarization.
    // Requires:
    //   - ChatRepository::find_chats_needing_summary()
    //   - MessageRepository::find_non_compressed_by_chat()
    //   - MessageRepository::mark_compressed()
    //   - LLM summarization call via ProviderResolver
    #[allow(clippy::unused_async)]
    async fn scan_and_summarize(&self, _cancel: &CancellationToken) -> anyhow::Result<()> {
        debug!("thread summary scan: no implementation yet (stub)");
        Ok(())
    }
}
