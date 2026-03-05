//! Thread summary worker — compresses chat history via LLM summarization.
//!
//! Periodically scans for chats that need summarization based on:
//! - message count exceeding a threshold (default: 20)
//! - user turn count exceeding a threshold (default: every 15 turns)
//!
//! For each qualifying chat, the worker loads the previous summary + recent
//! messages, calls the LLM for summarization (`requester_type=system`), saves
//! the new summary, and marks processed messages as `is_archived = true`.
//!
//! On failure the previous summary is kept and messages are NOT marked
//! archived, ensuring safe retry on the next scan.

use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use modkit_security::{AccessScope, SecurityContext};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::ThreadSummaryConfig;
use crate::domain::ports::WorkersMetricsPort;
use crate::domain::repos::{
    ChatRepository, MessageRepository, ThreadSummaryRepository, UpsertThreadSummaryParams,
};
use crate::domain::service::DbProvider;
use crate::infra::db::entity::message::MessageRole;
use crate::infra::llm::request::{
    Feature, LlmMessage, LlmRequestBuilder, RequestMetadata, RequestType,
};
use crate::infra::llm::LlmProvider;

const SYSTEM_SUBJECT_ID: Uuid = Uuid::nil();

const SUMMARIZATION_PROMPT: &str = "\
You are a summarization assistant. Produce a concise summary of the conversation below.

Guidelines:
- Capture key topics, decisions, conclusions, and action items.
- Preserve important facts, data points, and code snippets.
- If a previous summary exists, merge it with the new messages to produce a single updated summary.
- Keep the summary as short as possible while retaining all critical context needed to continue the conversation.
- Output only the summary text, no preamble.";

/// Background worker that compresses chat history via LLM summarization.
pub struct ThreadSummaryWorker<CR: ChatRepository, MR: MessageRepository> {
    db: Arc<DbProvider>,
    config: ThreadSummaryConfig,
    metrics: Arc<dyn WorkersMetricsPort>,
    llm: Arc<dyn LlmProvider>,
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
        llm: Arc<dyn LlmProvider>,
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
            llm,
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

    #[allow(clippy::cognitive_complexity)]
    async fn scan_and_summarize(&self, cancel: &CancellationToken) -> anyhow::Result<()> {
        let conn = self.db.conn().context("thread summary: DB connection")?;
        let scope = AccessScope::allow_all();

        let chat_ids = self
            .chat_repo
            .find_chats_needing_summary(
                &conn,
                &scope,
                self.config.msg_count_threshold,
                self.config.turn_threshold,
            )
            .await
            .context("find chats needing summary")?;

        if chat_ids.is_empty() {
            debug!("thread summary scan: no chats need summarization");
            return Ok(());
        }

        info!(count = chat_ids.len(), "thread summary scan: found qualifying chats");

        for chat_id in &chat_ids {
            if cancel.is_cancelled() {
                debug!("thread summary scan interrupted by cancellation");
                break;
            }

            if let Err(e) = self.summarize_chat(&conn, &scope, *chat_id).await {
                self.metrics.summary_runs_total("error");
                warn!(error = %e, %chat_id, "failed to summarize chat");
            }
        }

        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    async fn summarize_chat(
        &self,
        conn: &modkit_db::secure::DbConn<'_>,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> anyhow::Result<()> {
        let chat = self
            .chat_repo
            .get(conn, scope, chat_id)
            .await
            .context("load chat")?
            .ok_or_else(|| anyhow::anyhow!("chat {chat_id} not found or deleted"))?;

        let existing_summary = self
            .thread_summary_repo
            .get_by_chat_id(conn, scope, chat_id)
            .await
            .context("load existing summary")?;

        let messages = self
            .message_repo
            .find_non_archived_by_chat(conn, scope, chat_id)
            .await
            .context("load non-archived messages")?;

        let Some(last_msg) = messages.last() else {
            debug!(%chat_id, "no non-archived messages, skipping");
            return Ok(());
        };
        let last_message_id = last_msg.id;

        let user_content = build_user_prompt(
            existing_summary.as_ref().map(|s| s.summary_text.as_str()),
            &messages,
        );

        let model = if self.config.summary_model.is_empty() {
            chat.model.clone()
        } else {
            self.config.summary_model.clone()
        };

        let request = LlmRequestBuilder::new(&model)
            .system_instructions(SUMMARIZATION_PROMPT)
            .message(LlmMessage::user(user_content))
            .max_output_tokens(self.config.max_summary_tokens)
            .metadata(RequestMetadata {
                tenant_id: chat.tenant_id.to_string(),
                user_id: SYSTEM_SUBJECT_ID.to_string(),
                chat_id: chat_id.to_string(),
                request_type: RequestType::Summary,
                feature: Feature::None,
            })
            .build_non_streaming();

        let ctx = SecurityContext::builder()
            .subject_id(SYSTEM_SUBJECT_ID)
            .subject_tenant_id(chat.tenant_id)
            .subject_type("system")
            .build()
            .context("build system SecurityContext")?;

        let result = match self.llm.complete(ctx, request).await {
            Ok(r) => r,
            Err(e) => {
                self.metrics.summary_runs_total("fallback");
                warn!(
                    error = %e,
                    %chat_id,
                    "LLM summarization failed, keeping previous summary"
                );
                return Ok(());
            }
        };

        if result.content.trim().is_empty() {
            self.metrics.summary_runs_total("fallback");
            warn!(%chat_id, "LLM returned empty summary, keeping previous");
            return Ok(());
        }

        #[allow(clippy::cast_possible_truncation)]
        let token_estimate = result.usage.output_tokens as i32;

        let params = UpsertThreadSummaryParams {
            id: Uuid::new_v4(),
            tenant_id: chat.tenant_id,
            chat_id,
            summary_text: result.content,
            summarized_up_to: last_message_id,
            token_estimate,
        };

        self.thread_summary_repo
            .upsert(conn, scope, params)
            .await
            .context("upsert thread summary")?;

        let archived_count = self
            .message_repo
            .mark_archived(conn, scope, chat_id, last_message_id)
            .await
            .context("mark messages as archived")?;

        self.metrics.summary_runs_total("success");

        info!(
            %chat_id,
            messages_archived = archived_count,
            token_estimate,
            "chat summarized successfully"
        );

        Ok(())
    }
}

fn build_user_prompt(
    existing_summary: Option<&str>,
    messages: &[crate::infra::db::entity::message::Model],
) -> String {
    let mut prompt = String::with_capacity(4096);

    prompt.push_str("[Previous Summary]\n");
    match existing_summary {
        Some(s) if !s.is_empty() => prompt.push_str(s),
        _ => prompt.push_str("(none)"),
    }
    prompt.push_str("\n\n[Recent Messages]\n");

    for msg in messages {
        let role_label = match msg.role {
            MessageRole::User => "User",
            MessageRole::Assistant => "Assistant",
            MessageRole::System => "System",
        };
        writeln!(prompt, "{role_label}: {}", msg.content).ok();
    }

    prompt
}
