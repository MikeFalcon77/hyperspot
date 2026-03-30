//! Thread summary outbox handler - processes `thread_summary` queue events.
//!
//! Runs as part of the outbox pipeline (leased strategy). All replicas
//! process events in parallel, partitioned by `chat_id`. No leader election needed.
//!
//! **P1**: working skeleton with placeholder summary generation (simple concatenation).
//! Real LLM call deferred to P2.

use std::sync::Arc;

use async_trait::async_trait;
use modkit_db::outbox::{LeasedMessageHandler, MessageResult, OutboxMessage};
use tracing::warn;
use modkit_db::outbox::{HandlerResult, MessageHandler, OutboxMessage};
use modkit_db::DBProvider;
use modkit_security::AccessScope;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::domain::ports::MiniChatMetricsPort;
use crate::domain::repos::{
    SummaryFrontier, ThreadSummaryRepository, ThreadSummaryTaskPayload,
};
use crate::infra::db::entity::message::MessageRole;

type DbProvider = DBProvider<modkit_db::DbError>;
type MessageRepo = crate::infra::db::repo::message_repo::MessageRepository;
type ThreadSummaryRepo = crate::infra::db::repo::thread_summary_repo::ThreadSummaryRepository;

pub struct ThreadSummaryDeps {
    pub db: Arc<DbProvider>,
    pub thread_summary_repo: Arc<ThreadSummaryRepo>,
    pub message_repo: Arc<MessageRepo>,
    pub outbox_enqueuer: Arc<dyn crate::domain::repos::OutboxEnqueuer>,
    pub metrics: Arc<dyn MiniChatMetricsPort>,
}

pub struct ThreadSummaryHandler {
    deps: Arc<ThreadSummaryDeps>,
}

impl ThreadSummaryHandler {
    pub fn new(deps: Arc<ThreadSummaryDeps>) -> Self {
        Self { deps }
    }
}

#[async_trait]
impl LeasedMessageHandler for ThreadSummaryHandler {
    async fn handle(&self, msg: &OutboxMessage) -> HandlerResult {
        // 1. Deserialize payload
        let payload: ThreadSummaryTaskPayload = match serde_json::from_slice(&msg.payload) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    partition_id = msg.partition_id,
                    seq = msg.seq,
                    error = %e,
                    "thread summary: invalid payload, dead-lettering"
                );
                return HandlerResult::Reject {
                    reason: format!("payload deserialization failed: {e}"),
                };
            }
        };

        let base_frontier = match (
            &payload.base_frontier_created_at,
            &payload.base_frontier_message_id,
        ) {
            (Some(ca), Some(mid)) => Some(SummaryFrontier {
                created_at: *ca,
                message_id: *mid,
            }),
            _ => None,
        };

        let target_frontier = SummaryFrontier {
            created_at: payload.frozen_target_created_at,
            message_id: payload.frozen_target_message_id,
        };

        // 2. Pre-check: verify stored frontier still matches base_frontier
        let conn = match self.deps.db.conn() {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    chat_id = %payload.chat_id,
                    error = %e,
                    "thread summary: DB connection failed"
                );
                return HandlerResult::Retry {
                    reason: format!("db connection: {e}"),
                };
            }
        };

        let scope = AccessScope::for_tenant(payload.tenant_id);

        let current = self
            .deps
            .thread_summary_repo
            .get_latest(&conn, &scope, payload.chat_id)
            .await;

        match &current {
            Ok(Some(existing)) => {
                if base_frontier.as_ref() != Some(&existing.frontier) {
                    info!(
                        chat_id = %payload.chat_id,
                        "thread summary: frontier already advanced, skipping"
                    );
                    self.deps.metrics.record_thread_summary_cas_conflict();
                    return HandlerResult::Success;
                }
            }
            Ok(None) => {
                if base_frontier.is_some() {
                    warn!(
                        chat_id = %payload.chat_id,
                        "thread summary: expected frontier but none found, skipping"
                    );
                    return HandlerResult::Success;
                }
            }
            Err(e) => {
                warn!(
                    chat_id = %payload.chat_id,
                    error = %e,
                    "thread summary: pre-check query failed"
                );
                return HandlerResult::Retry {
                    reason: format!("pre-check query: {e}"),
                };
            }
        }

        // 3. Load messages in range
        let messages = match crate::domain::repos::MessageRepository::fetch_messages_in_range(
            self.deps.message_repo.as_ref(),
            &conn,
            &scope,
            payload.chat_id,
            base_frontier.as_ref(),
            &target_frontier,
        )
        .await
        {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    chat_id = %payload.chat_id,
                    error = %e,
                    "thread summary: message fetch failed"
                );
                return HandlerResult::Retry {
                    reason: format!("message fetch: {e}"),
                };
            }
        };

        if messages.is_empty() {
            debug!(
                chat_id = %payload.chat_id,
                "thread summary: no messages in range, skipping"
            );
            return HandlerResult::Success;
        }

        // 4. Generate summary (P1: placeholder -- real LLM call in P2)
        let existing_summary = current
            .as_ref()
            .ok()
            .and_then(|c| c.as_ref())
            .map(|s| s.content.as_str());

        let summary_text = build_summary_placeholder(existing_summary, &messages);
        let token_estimate = (summary_text.len() / 4) as i32; // rough estimate

        // 5. CAS-protected atomic commit
        let deps = Arc::clone(&self.deps);
        let base_clone = base_frontier.clone();
        let target_clone = target_frontier.clone();
        let summary_clone = summary_text;
        let msg_count = messages.len();

        let cas_result = self
            .deps
            .db
            .transaction(|tx| {
                let deps = Arc::clone(&deps);
                let base_clone = base_clone.clone();
                let target_clone = target_clone.clone();
                let summary_clone = summary_clone.clone();
                let scope = scope.clone();
                Box::pin(async move {
                    // 5a. Upsert summary with CAS
                    let rows = deps
                        .thread_summary_repo
                        .upsert_with_cas(
                            tx,
                            payload.chat_id,
                            payload.tenant_id,
                            base_clone.as_ref(),
                            &target_clone,
                            &summary_clone,
                            token_estimate,
                        )
                        .await
                        .map_err(|e| modkit_db::DbError::Other(anyhow::anyhow!("{e}")))?;

                    if rows == 0 {
                        return Ok(false);
                    }

                    // 5b. Mark messages as compressed
                    crate::domain::repos::MessageRepository::mark_messages_compressed(
                        deps.message_repo.as_ref(),
                        tx,
                        &scope,
                        payload.chat_id,
                        base_clone.as_ref(),
                        &target_clone,
                    )
                    .await
                    .map_err(|e| modkit_db::DbError::Other(anyhow::anyhow!("{e}")))?;

                    Ok(true)
                })
            })
            .await;

        match cas_result {
            Ok(true) => {
                // Post-commit: wake outbox sequencer for any enqueued events.
                self.deps.outbox_enqueuer.flush();
                self.deps
                    .metrics
                    .record_thread_summary_execution("success");
                info!(
                    chat_id = %payload.chat_id,
                    messages_compressed = msg_count,
                    "thread summary: committed successfully"
                );
                HandlerResult::Success
            }
            Ok(false) => {
                self.deps.metrics.record_thread_summary_cas_conflict();
                info!(
                    chat_id = %payload.chat_id,
                    "thread summary: CAS conflict on commit, skipping"
                );
                HandlerResult::Success
            }
            Err(e) => {
                warn!(
                    chat_id = %payload.chat_id,
                    error = %e,
                    "thread summary: commit failed"
                );
                self.deps
                    .metrics
                    .record_thread_summary_execution("retry");
                HandlerResult::Retry {
                    reason: format!("commit failed: {e}"),
                }
            }
        }
    }
}

/// Build a placeholder summary for P1 (real LLM call deferred to P2).
fn build_summary_placeholder(
    existing_summary: Option<&str>,
    messages: &[crate::infra::db::entity::message::Model],
) -> String {
    let mut summary = String::new();

    if let Some(prev) = existing_summary {
        summary.push_str(prev);
        summary.push_str("\n\n--- New messages ---\n\n");
    }

    for msg in messages {
        let role = match msg.role {
            MessageRole::User => "User",
            MessageRole::Assistant => "Assistant",
            MessageRole::System => "System",
        };
        let content = if msg.content.len() > 500 {
            format!("{}...", &msg.content[..500])
        } else {
            msg.content.clone()
        };
        summary.push_str(&format!("{role}: {content}\n"));
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use modkit_db::outbox::LeasedMessageHandler;

    #[test]
    fn rejects_invalid_payload() {
        let payload = b"not valid json";
        let result: Result<ThreadSummaryTaskPayload, _> = serde_json::from_slice(payload);
        assert!(result.is_err());
    }

    #[test]
    fn placeholder_summary_builds_correctly() {
        use crate::infra::db::entity::message::Model;
        use time::OffsetDateTime;
        use uuid::Uuid;

        let msg = Model {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            chat_id: Uuid::new_v4(),
            request_id: Some(Uuid::new_v4()),
            role: MessageRole::User,
            content: "Hello world".to_owned(),
            content_type: "text/plain".to_owned(),
            token_estimate: 5,
            provider_response_id: None,
            request_kind: None,
            features_used: serde_json::json!([]),
            input_tokens: 0,
            output_tokens: 0,
            cache_read_input_tokens: 0,
            cache_write_input_tokens: 0,
            reasoning_tokens: 0,
            model: None,
            is_compressed: false,
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };

        let summary = build_summary_placeholder(None, &[msg]);
        assert!(summary.contains("User: Hello world"));
    }

    #[test]
    fn placeholder_summary_appends_to_existing() {
        use crate::infra::db::entity::message::Model;
        use time::OffsetDateTime;
        use uuid::Uuid;

        let msg = Model {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            chat_id: Uuid::new_v4(),
            request_id: Some(Uuid::new_v4()),
            role: MessageRole::Assistant,
            content: "I can help with that.".to_owned(),
            content_type: "text/plain".to_owned(),
            token_estimate: 10,
            provider_response_id: None,
            request_kind: None,
            features_used: serde_json::json!([]),
            input_tokens: 0,
            output_tokens: 0,
            cache_read_input_tokens: 0,
            cache_write_input_tokens: 0,
            reasoning_tokens: 0,
            model: None,
            is_compressed: false,
            created_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        };

        let summary = build_summary_placeholder(Some("Previous summary"), &[msg]);
        assert!(summary.starts_with("Previous summary"));
        assert!(summary.contains("--- New messages ---"));
        assert!(summary.contains("Assistant: I can help with that."));
    }
}
