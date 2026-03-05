use std::sync::Arc;

use authz_resolver_sdk::PolicyEnforcer;
use futures::StreamExt;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use oagw_sdk::SecurityContext;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::api::rest::dto::{DoneData, ErrorData, StreamEvent};
use crate::config::StreamingConfig;
use crate::domain::error::DomainError;
use crate::domain::repos::{
    ChatRepository, CreateTurnParams, InsertUserMessageParams, MessageRepository, TurnRepository,
};
use crate::infra::db::entity::chat_turn::{Model as TurnModel, TurnState};
use crate::infra::llm::{
    ClientSseEvent, LlmMessage, LlmProvider, LlmProviderError, LlmRequestBuilder, TerminalOutcome,
    Usage,
};

use super::DbProvider;

// ════════════════════════════════════════════════════════════════════════════
// StreamTerminal — service-level terminal classification
// ════════════════════════════════════════════════════════════════════════════

/// How the stream ended at the service level.
///
/// Maps from the provider-level [`TerminalOutcome`] with an additional
/// `Cancelled` variant for client/server-initiated cancellation.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTerminal {
    /// Provider completed successfully — full response received.
    Completed,
    /// Provider stopped early (e.g. `max_output_tokens` hit).
    Incomplete,
    /// Provider or stream-level error.
    Failed,
    /// Cancelled (client disconnect or server-initiated).
    Cancelled,
}

// ════════════════════════════════════════════════════════════════════════════
// StreamOutcome — returned from run_stream()
// ════════════════════════════════════════════════════════════════════════════

/// Summary of a finished stream, returned from [`StreamService::run_stream()`].
///
/// Used by P1 for logging and metrics, and by P4 for CAS finalization.
#[domain_model]
#[derive(Debug)]
#[allow(dead_code)]
pub struct StreamOutcome {
    /// How the stream ended.
    pub terminal: StreamTerminal,
    /// Accumulated assistant text from delta events.
    pub accumulated_text: String,
    /// Token usage from the provider (if available).
    pub usage: Option<Usage>,
    /// The model actually used by the provider.
    pub effective_model: String,
    /// Normalized error code (e.g. `rate_limited`, `provider_timeout`).
    pub error_code: Option<String>,
    /// Provider response ID (e.g. `OpenAI` `response_id`).
    pub provider_response_id: Option<String>,
    /// Whether usage was from a partial/incomplete provider response.
    pub provider_partial_usage: bool,
}

// ════════════════════════════════════════════════════════════════════════════
// StreamError — pre-stream error before SSE connection opens
// ════════════════════════════════════════════════════════════════════════════

/// Pre-stream error — returned from [`StreamService::run_stream()`] before
/// the SSE connection opens. The handler maps these to JSON error responses.
#[domain_model]
#[derive(Debug)]
#[allow(dead_code)]
pub enum StreamError {
    /// Idempotent replay: a turn with this `request_id` already exists.
    Replay { turn: Box<TurnModel> },
    /// Conflict: another turn is already running for this chat.
    Conflict { code: String, message: String },
    /// Turn creation or pre-stream DB operation failed.
    TurnCreationFailed { source: DomainError },
}

// ════════════════════════════════════════════════════════════════════════════
// PersistenceCtx — bundled context for CAS finalization in the spawned task
// ════════════════════════════════════════════════════════════════════════════

/// Persistence context cloned into the spawned provider task for CAS
/// finalization after stream completion. `None` in unit tests.
#[domain_model]
struct PersistenceCtx<TR: TurnRepository, MR: MessageRepository> {
    db: Arc<DbProvider>,
    turn_repo: Arc<TR>,
    message_repo: Arc<MR>,
    scope: AccessScope,
    turn_id: Uuid,
    tenant_id: Uuid,
    chat_id: Uuid,
    request_id: Uuid,
    /// Pre-generated assistant message ID, also sent in `DoneData`.
    message_id: Uuid,
}

// ════════════════════════════════════════════════════════════════════════════
// Error normalization
// ════════════════════════════════════════════════════════════════════════════

/// Normalize an [`LlmProviderError`] to a `(code, message)` pair for the SSE
/// error event. Messages are already sanitized by the infra layer.
fn normalize_error(err: &LlmProviderError) -> (String, String) {
    match err {
        LlmProviderError::RateLimited { .. } => (
            "rate_limited".to_owned(),
            "Rate limited by provider".to_owned(),
        ),
        LlmProviderError::Timeout => (
            "provider_timeout".to_owned(),
            "Provider request timed out".to_owned(),
        ),
        LlmProviderError::ProviderError { message, .. } => {
            ("provider_error".to_owned(), message.clone())
        }
        LlmProviderError::InvalidResponse { detail } => (
            "provider_error".to_owned(),
            crate::infra::llm::sanitize_provider_message(detail),
        ),
        LlmProviderError::ProviderUnavailable => (
            "provider_error".to_owned(),
            "Provider is currently unavailable".to_owned(),
        ),
        LlmProviderError::StreamError(e) => (
            "provider_error".to_owned(),
            crate::infra::llm::sanitize_provider_message(&e.to_string()),
        ),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// StreamService
// ════════════════════════════════════════════════════════════════════════════

/// Service handling SSE streaming and turn orchestration.
///
/// In P1 this is a stateless proxy: it builds an LLM request, streams
/// provider events through a bounded channel, and returns a `StreamOutcome`.
/// P2 adds turn persistence (pre-stream checks + CAS finalization).
#[domain_model]
#[allow(dead_code)]
pub struct StreamService<TR: TurnRepository, MR: MessageRepository, CR: ChatRepository> {
    db: Arc<DbProvider>,
    turn_repo: Arc<TR>,
    message_repo: Arc<MR>,
    chat_repo: Arc<CR>,
    enforcer: PolicyEnforcer,
    llm: Arc<dyn LlmProvider>,
    streaming_config: StreamingConfig,
}

impl<TR: TurnRepository + 'static, MR: MessageRepository + 'static, CR: ChatRepository>
    StreamService<TR, MR, CR>
{
    pub(crate) fn new(
        db: Arc<DbProvider>,
        turn_repo: Arc<TR>,
        message_repo: Arc<MR>,
        chat_repo: Arc<CR>,
        enforcer: PolicyEnforcer,
        llm: Arc<dyn LlmProvider>,
        streaming_config: StreamingConfig,
    ) -> Self {
        Self {
            db,
            turn_repo,
            message_repo,
            chat_repo,
            enforcer,
            llm,
            streaming_config,
        }
    }

    /// The configured channel capacity for the provider->writer mpsc channel.
    pub(crate) fn channel_capacity(&self) -> usize {
        usize::from(self.streaming_config.sse_channel_capacity)
    }

    /// The configured ping interval in seconds.
    pub(crate) fn ping_interval_secs(&self) -> u64 {
        u64::from(self.streaming_config.sse_ping_interval_seconds)
    }

    /// Perform pre-stream checks (idempotency, parallel guard, message/turn
    /// creation) then spawn the provider task.
    ///
    /// Returns `Err(StreamError)` if pre-stream validation fails (before SSE
    /// connection opens). The handler maps these to JSON error responses.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_stream(
        &self,
        ctx: SecurityContext,
        chat_id: Uuid,
        request_id: Uuid,
        content: String,
        model: String,
        cancel: CancellationToken,
        tx: mpsc::Sender<StreamEvent>,
    ) -> Result<tokio::task::JoinHandle<StreamOutcome>, StreamError> {
        let tenant_id = ctx.subject_tenant_id();
        let user_id = ctx.subject_id();
        let scope = AccessScope::for_tenant(tenant_id);

        // Non-transactional connection for pre-stream checks (D6)
        let conn = self
            .db
            .conn()
            .map_err(|e| StreamError::TurnCreationFailed {
                source: DomainError::from(e),
            })?;

        // ── Idempotency check ──
        if let Some(existing_turn) = self
            .turn_repo
            .find_by_chat_and_request_id(&conn, &scope, chat_id, request_id)
            .await
            .map_err(|e| StreamError::TurnCreationFailed { source: e })?
        {
            return Err(StreamError::Replay {
                turn: Box::new(existing_turn),
            });
        }

        // ── Parallel turn guard ──
        if let Some(running) = self
            .turn_repo
            .find_running_by_chat_id(&conn, &scope, chat_id)
            .await
            .map_err(|e| StreamError::TurnCreationFailed { source: e })?
        {
            return Err(StreamError::Conflict {
                code: "turn_already_running".to_owned(),
                message: format!("Chat {} already has a running turn {}", chat_id, running.id),
            });
        }

        // ── Insert user message + create turn (atomic) ──
        let user_msg_id = Uuid::new_v4();
        let turn_id = Uuid::new_v4();
        let requester_type = ctx.subject_type().unwrap_or("user").to_owned();
        let effective_model = model.clone();

        let message_repo = Arc::clone(&self.message_repo);
        let turn_repo = Arc::clone(&self.turn_repo);
        let content_clone = content.clone();
        let scope_tx = scope.clone();

        self.db
            .transaction(|tx| {
                Box::pin(async move {
                    message_repo
                        .insert_user_message(
                            tx,
                            &scope_tx,
                            InsertUserMessageParams {
                                id: user_msg_id,
                                tenant_id,
                                chat_id,
                                request_id,
                                content: content_clone,
                            },
                        )
                        .await
                        .map_err(|e| modkit_db::DbError::Other(anyhow::anyhow!(e)))?;

                    turn_repo
                        .create_turn(
                            tx,
                            &scope_tx,
                            CreateTurnParams {
                                id: turn_id,
                                tenant_id,
                                chat_id,
                                request_id,
                                requester_type,
                                requester_user_id: Some(user_id),
                                reserve_tokens: None,
                                max_output_tokens_applied: None,
                                reserved_credits_micro: None,
                                policy_version_applied: None,
                                effective_model: Some(effective_model),
                                minimal_generation_floor_applied: None,
                            },
                        )
                        .await
                        .map_err(|e| modkit_db::DbError::Other(anyhow::anyhow!(e)))?;

                    Ok(())
                })
            })
            .await
            .map_err(|e| StreamError::TurnCreationFailed {
                source: DomainError::from(e),
            })?;

        // Pre-generate assistant message ID (sent in DoneData and used in CAS)
        let message_id = Uuid::new_v4();

        let persist = PersistenceCtx {
            db: Arc::clone(&self.db),
            turn_repo: Arc::clone(&self.turn_repo),
            message_repo: Arc::clone(&self.message_repo),
            scope,
            turn_id,
            tenant_id,
            chat_id,
            request_id,
            message_id,
        };

        Ok(spawn_provider_task(
            Arc::clone(&self.llm),
            ctx,
            content,
            model,
            cancel,
            tx,
            Some(persist),
        ))
    }
}

/// Core provider task: reads from the LLM, translates events, and returns
/// a [`StreamOutcome`]. After the stream ends, CAS-finalizes the turn if
/// a persistence context is provided.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::let_underscore_must_use,
    clippy::cast_possible_truncation
)]
fn spawn_provider_task<TR: TurnRepository + 'static, MR: MessageRepository + 'static>(
    llm: Arc<dyn LlmProvider>,
    ctx: SecurityContext,
    content: String,
    model: String,
    cancel: CancellationToken,
    tx: mpsc::Sender<StreamEvent>,
    persist: Option<PersistenceCtx<TR, MR>>,
) -> tokio::task::JoinHandle<StreamOutcome> {
    tokio::spawn(async move {
        let stream_start = std::time::Instant::now();
        let mut first_token_time: Option<std::time::Duration> = None;
        let msg_id_str = persist.as_ref().map(|p| p.message_id.to_string());

        // Build the LLM request
        let request = LlmRequestBuilder::new(&model)
            .message(LlmMessage::user(&content))
            .build_streaming();

        // Call the provider to start streaming
        let stream_result = llm.stream(ctx, request, cancel.clone()).await;

        let mut provider_stream = match stream_result {
            Ok(s) => s,
            Err(e) => {
                // Provider failed before any events — send error and return.
                let (code, message) = normalize_error(&e);
                let _ = tx
                    .send(StreamEvent::Error(ErrorData {
                        code: code.clone(),
                        message,
                    }))
                    .await;

                // CAS finalize: mark turn as failed
                if let Some(ref p) = persist {
                    cas_finalize_terminal(p, TurnState::Failed, Some(code.clone()), None).await;
                }

                return StreamOutcome {
                    terminal: StreamTerminal::Failed,
                    accumulated_text: String::new(),
                    usage: None,
                    effective_model: model,
                    error_code: Some(code),
                    provider_response_id: None,
                    provider_partial_usage: false,
                };
            }
        };

        // Read events from provider, translate and forward through channel
        let mut accumulated_text = String::new();
        let mut cancelled = false;

        loop {
            tokio::select! {
                biased;

                () = cancel.cancelled() => {
                    debug!("stream cancelled, aborting provider");
                    provider_stream.cancel();
                    cancelled = true;
                    break;
                }

                event = provider_stream.next() => {
                    match event {
                        Some(Ok(client_event)) => {
                            if let ClientSseEvent::Delta { ref content, .. } = client_event {
                                if first_token_time.is_none() {
                                    let ttft = stream_start.elapsed();
                                    first_token_time = Some(ttft);
                                    debug!(
                                        time_to_first_token_ms = ttft.as_millis() as u64,
                                        model = %model,
                                        "first token received"
                                    );
                                }
                                accumulated_text.push_str(content);
                            }
                            let stream_event = StreamEvent::from(client_event);
                            if tx.send(stream_event).await.is_err() {
                                // Receiver dropped (client disconnect handled by relay)
                                debug!("channel closed, exiting provider task");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "provider stream error");
                            let (code, message) =
                                normalize_error(&LlmProviderError::StreamError(e));
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;

                            // CAS finalize: mark turn as failed
                            if let Some(ref p) = persist {
                                cas_finalize_terminal(
                                    p,
                                    TurnState::Failed,
                                    Some(code.clone()),
                                    None,
                                ).await;
                            }

                            let has_partial = !accumulated_text.is_empty();
                            return StreamOutcome {
                                terminal: StreamTerminal::Failed,
                                accumulated_text,
                                usage: None,
                                effective_model: model,
                                error_code: Some(code),
                                provider_response_id: None,
                                provider_partial_usage: has_partial,
                            };
                        }
                        None => {
                            // Stream ended — terminal captured by ProviderStream
                            break;
                        }
                    }
                }
            }
        }

        if cancelled {
            let elapsed = stream_start.elapsed();
            info!(
                terminal = "cancelled",
                model = %model,
                duration_ms = elapsed.as_millis() as u64,
                "stream cancelled"
            );

            // CAS finalize: mark turn as cancelled
            if let Some(ref p) = persist {
                cas_finalize_terminal(p, TurnState::Cancelled, None, None).await;
            }

            return StreamOutcome {
                terminal: StreamTerminal::Cancelled,
                accumulated_text,
                usage: None,
                effective_model: model,
                error_code: None,
                provider_response_id: None,
                provider_partial_usage: false,
            };
        }

        // Extract the terminal outcome from the provider stream
        let terminal = provider_stream.into_outcome().await;

        match terminal {
            TerminalOutcome::Completed {
                usage,
                content: _,
                citations,
                response_id,
                ..
            } => {
                // Send citations if present
                if !citations.is_empty() {
                    let _ = tx
                        .send(StreamEvent::Citations(
                            crate::api::rest::dto::CitationsData { items: citations },
                        ))
                        .await;
                }
                // Send Done terminal
                let _ = tx
                    .send(StreamEvent::Done(Box::new(DoneData {
                        message_id: msg_id_str,
                        usage: Some(usage),
                        effective_model: model.clone(),
                        selected_model: model.clone(),
                        quota_decision: "allow".into(), // P3 provides real decision
                        downgrade_from: None,           // P3 provides
                        downgrade_reason: None,         // P3 provides
                    })))
                    .await;
                let elapsed = stream_start.elapsed();
                info!(
                    terminal = "completed",
                    model = %model,
                    input_tokens = usage.input_tokens,
                    output_tokens = usage.output_tokens,
                    duration_ms = elapsed.as_millis() as u64,
                    "stream completed"
                );

                // CAS finalize: insert assistant message + mark turn completed
                if let Some(ref p) = persist {
                    cas_finalize_completed(
                        p,
                        &accumulated_text,
                        Some(usage),
                        Some(model.clone()),
                        Some(response_id.clone()),
                    )
                    .await;
                }

                StreamOutcome {
                    terminal: StreamTerminal::Completed,
                    accumulated_text,
                    usage: Some(usage),
                    effective_model: model,
                    error_code: None,
                    provider_response_id: Some(response_id),
                    provider_partial_usage: false,
                }
            }
            TerminalOutcome::Incomplete { usage, reason, .. } => {
                let _ = tx
                    .send(StreamEvent::Done(Box::new(DoneData {
                        message_id: msg_id_str,
                        usage: Some(usage),
                        effective_model: model.clone(),
                        selected_model: model.clone(),
                        quota_decision: "allow".into(),
                        downgrade_from: None,
                        downgrade_reason: None,
                    })))
                    .await;
                let elapsed = stream_start.elapsed();
                warn!(
                    terminal = "incomplete",
                    model = %model,
                    reason = %reason,
                    duration_ms = elapsed.as_millis() as u64,
                    "stream incomplete"
                );

                // CAS finalize: insert assistant message + mark turn completed
                // (incomplete is still a valid response, just truncated)
                if let Some(ref p) = persist {
                    cas_finalize_completed(
                        p,
                        &accumulated_text,
                        Some(usage),
                        Some(model.clone()),
                        None, // Incomplete has no response_id
                    )
                    .await;
                }

                StreamOutcome {
                    terminal: StreamTerminal::Incomplete,
                    accumulated_text,
                    usage: Some(usage),
                    effective_model: model,
                    error_code: Some(format!("incomplete:{reason}")),
                    provider_response_id: None,
                    provider_partial_usage: false,
                }
            }
            TerminalOutcome::Failed { error, usage, .. } => {
                let (code, message) = normalize_error(&error);
                let _ = tx
                    .send(StreamEvent::Error(ErrorData {
                        code: code.clone(),
                        message,
                    }))
                    .await;
                let elapsed = stream_start.elapsed();
                warn!(
                    terminal = "failed",
                    model = %model,
                    error_code = %code,
                    duration_ms = elapsed.as_millis() as u64,
                    "stream failed"
                );

                // CAS finalize: mark turn as failed
                if let Some(ref p) = persist {
                    cas_finalize_terminal(p, TurnState::Failed, Some(code.clone()), None).await;
                }

                StreamOutcome {
                    terminal: StreamTerminal::Failed,
                    accumulated_text,
                    usage,
                    effective_model: model,
                    error_code: Some(code),
                    provider_response_id: None,
                    provider_partial_usage: usage.is_some(),
                }
            }
        }
    })
}

// ════════════════════════════════════════════════════════════════════════════
// CAS finalization — delegates to shared finalize module
// ════════════════════════════════════════════════════════════════════════════

use super::finalize::{self, CompletedFinalizeParams};

/// Fire-and-forget CAS finalization to a completed state.
async fn cas_finalize_completed<TR: TurnRepository, MR: MessageRepository>(
    p: &PersistenceCtx<TR, MR>,
    text: &str,
    usage: Option<Usage>,
    model: Option<String>,
    provider_response_id: Option<String>,
) {
    finalize::persist_finalize_completed(
        &p.db,
        &*p.turn_repo,
        &*p.message_repo,
        &p.scope,
        CompletedFinalizeParams {
            turn_id: p.turn_id,
            message_id: p.message_id,
            tenant_id: p.tenant_id,
            chat_id: p.chat_id,
            request_id: p.request_id,
            text: text.to_owned(),
            input_tokens: usage.map(|u| u.input_tokens),
            output_tokens: usage.map(|u| u.output_tokens),
            model,
            provider_response_id,
        },
    )
    .await;
}

/// Fire-and-forget CAS finalization to a terminal state.
async fn cas_finalize_terminal<TR: TurnRepository, MR: MessageRepository>(
    p: &PersistenceCtx<TR, MR>,
    state: TurnState,
    error_code: Option<String>,
    error_detail: Option<String>,
) {
    finalize::persist_finalize_terminal(
        &p.db,
        &*p.turn_repo,
        &p.scope,
        p.turn_id,
        state,
        error_code,
        error_detail,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::db::repo::message_repo::MessageRepository as MsgRepo;
    use crate::infra::db::repo::turn_repo::TurnRepository as TurnRepo;
    use crate::infra::llm::{
        LlmRequest, NonStreaming, ProviderStream, ResponseResult, Streaming, TranslatedEvent,
    };
    use futures::stream;
    use oagw_sdk::error::StreamingError;

    #[test]
    fn normalize_rate_limited() {
        let err = LlmProviderError::RateLimited {
            retry_after_secs: Some(30),
        };
        let (code, _) = normalize_error(&err);
        assert_eq!(code, "rate_limited");
    }

    #[test]
    fn normalize_timeout() {
        let (code, _) = normalize_error(&LlmProviderError::Timeout);
        assert_eq!(code, "provider_timeout");
    }

    #[test]
    fn normalize_provider_error() {
        let err = LlmProviderError::ProviderError {
            code: "bad_request".into(),
            message: "something went wrong".into(),
            raw_detail: None,
        };
        let (code, msg) = normalize_error(&err);
        assert_eq!(code, "provider_error");
        assert_eq!(msg, "something went wrong");
    }

    #[test]
    fn normalize_unavailable() {
        let (code, _) = normalize_error(&LlmProviderError::ProviderUnavailable);
        assert_eq!(code, "provider_error");
    }

    #[test]
    fn normalize_invalid_response() {
        let err = LlmProviderError::InvalidResponse {
            detail: "bad json".into(),
        };
        let (code, msg) = normalize_error(&err);
        assert_eq!(code, "provider_error");
        assert_eq!(msg, "bad json");
    }

    // ── Mock LlmProvider for integration tests ──

    /// A mock LLM provider that yields predefined events and a terminal outcome.
    #[allow(de0309_must_have_domain_model)]
    struct MockProvider {
        events: std::sync::Mutex<Vec<Result<TranslatedEvent, StreamingError>>>,
    }

    impl MockProvider {
        fn completed(deltas: &[&str]) -> Self {
            let mut events: Vec<Result<TranslatedEvent, StreamingError>> = deltas
                .iter()
                .map(|text| {
                    Ok(TranslatedEvent::Sse(ClientSseEvent::Delta {
                        r#type: "text",
                        content: (*text).to_owned(),
                    }))
                })
                .collect();

            let full_text: String = deltas.iter().copied().collect();
            events.push(Ok(TranslatedEvent::Terminal(TerminalOutcome::Completed {
                usage: Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                },
                response_id: "resp-test".to_owned(),
                content: full_text,
                citations: vec![],
                raw_response: serde_json::Value::Null,
            })));

            Self {
                events: std::sync::Mutex::new(events),
            }
        }

        fn failing() -> Self {
            Self {
                events: std::sync::Mutex::new(vec![Ok(TranslatedEvent::Terminal(
                    TerminalOutcome::Failed {
                        error: LlmProviderError::Timeout,
                        usage: None,
                        partial_content: String::new(),
                    },
                ))]),
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        async fn stream(
            &self,
            _ctx: SecurityContext,
            _request: LlmRequest<Streaming>,
            cancel: CancellationToken,
        ) -> Result<ProviderStream, LlmProviderError> {
            let events = self.events.lock().unwrap().drain(..).collect::<Vec<_>>();
            let inner = stream::iter(events);
            Ok(ProviderStream::new(inner, cancel))
        }

        async fn complete(
            &self,
            _ctx: SecurityContext,
            _request: LlmRequest<NonStreaming>,
        ) -> Result<ResponseResult, LlmProviderError> {
            unimplemented!("not needed for streaming tests")
        }
    }

    fn mock_ctx() -> SecurityContext {
        SecurityContext::anonymous()
    }

    // ── Integration tests ──

    /// 6.5: End-to-end stream with mock provider returning deltas + completed.
    #[tokio::test]
    async fn end_to_end_completed_stream() {
        let provider: Arc<dyn LlmProvider> =
            Arc::new(MockProvider::completed(&["Hello", ", ", "world!"]));
        let (tx, mut rx) = mpsc::channel::<StreamEvent>(32);
        let cancel = CancellationToken::new();

        let handle = spawn_provider_task::<TurnRepo, MsgRepo>(
            provider,
            mock_ctx(),
            "hi".into(),
            "test-model".into(),
            cancel,
            tx,
            None,
        );

        // Collect all events from the channel
        let mut events = Vec::new();
        while let Some(ev) = rx.recv().await {
            let is_term = ev.is_terminal();
            events.push(ev);
            if is_term {
                break;
            }
        }

        // Verify event sequence: 3 deltas + 1 done
        assert_eq!(events.len(), 4);
        assert!(matches!(events[0], StreamEvent::Delta(_)));
        assert!(matches!(events[1], StreamEvent::Delta(_)));
        assert!(matches!(events[2], StreamEvent::Delta(_)));
        assert!(matches!(events[3], StreamEvent::Done(_)));

        // Verify accumulated text in outcome
        let outcome = handle.await.expect("task should complete");
        assert_eq!(outcome.terminal, StreamTerminal::Completed);
        assert_eq!(outcome.accumulated_text, "Hello, world!");
        assert!(outcome.usage.is_some());
        assert_eq!(outcome.error_code, None);
        assert_eq!(outcome.provider_response_id.as_deref(), Some("resp-test"));
    }

    /// 6.5 variant: Provider fails before first event.
    #[tokio::test]
    async fn provider_error_produces_error_event() {
        let provider: Arc<dyn LlmProvider> = Arc::new(MockProvider::failing());
        let (tx, mut rx) = mpsc::channel::<StreamEvent>(32);
        let cancel = CancellationToken::new();

        let handle = spawn_provider_task::<TurnRepo, MsgRepo>(
            provider,
            mock_ctx(),
            "hi".into(),
            "test-model".into(),
            cancel,
            tx,
            None,
        );

        let mut events = Vec::new();
        while let Some(ev) = rx.recv().await {
            let is_term = ev.is_terminal();
            events.push(ev);
            if is_term {
                break;
            }
        }

        // Should get exactly one Error event
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], StreamEvent::Error(_)));

        let outcome = handle.await.expect("task should complete");
        assert_eq!(outcome.terminal, StreamTerminal::Failed);
        assert_eq!(outcome.error_code.as_deref(), Some("provider_timeout"));
    }

    /// 6.6: Cancellation mid-stream.
    #[tokio::test]
    async fn cancellation_stops_stream() {
        // A provider that yields one delta then blocks until cancelled.
        #[allow(de0309_must_have_domain_model)]
        struct SlowProvider;

        #[async_trait::async_trait]
        impl LlmProvider for SlowProvider {
            async fn stream(
                &self,
                _ctx: SecurityContext,
                _request: LlmRequest<Streaming>,
                cancel: CancellationToken,
            ) -> Result<ProviderStream, LlmProviderError> {
                let inner = stream::unfold(0u8, |state| async move {
                    if state == 0 {
                        Some((
                            Ok(TranslatedEvent::Sse(ClientSseEvent::Delta {
                                r#type: "text",
                                content: "partial".to_owned(),
                            })),
                            1,
                        ))
                    } else {
                        // Block until cancelled
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        None
                    }
                });
                Ok(ProviderStream::new(inner, cancel))
            }

            async fn complete(
                &self,
                _ctx: SecurityContext,
                _request: LlmRequest<NonStreaming>,
            ) -> Result<ResponseResult, LlmProviderError> {
                unimplemented!()
            }
        }

        let provider: Arc<dyn LlmProvider> = Arc::new(SlowProvider);
        let (tx, mut rx) = mpsc::channel::<StreamEvent>(32);
        let cancel = CancellationToken::new();

        let handle = spawn_provider_task::<TurnRepo, MsgRepo>(
            provider,
            mock_ctx(),
            "hi".into(),
            "test-model".into(),
            cancel.clone(),
            tx,
            None,
        );

        // Read the first delta
        let first = rx.recv().await.expect("should get first delta");
        assert!(matches!(first, StreamEvent::Delta(_)));

        // Cancel the stream
        cancel.cancel();

        // The provider task should exit
        let outcome = handle.await.expect("task should complete");
        assert_eq!(outcome.terminal, StreamTerminal::Cancelled);
        assert_eq!(outcome.accumulated_text, "partial");
    }
}
