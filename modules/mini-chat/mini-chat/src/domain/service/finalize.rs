//! Shared CAS finalization logic — the single universal finalization path.
//!
//! Per the `FinalizeTurn` invariant, **every terminal path** (streaming
//! completion, provider error, client disconnect, orphan watchdog) MUST
//! use these functions. No exceptions.
//!
//! TODO(P1): Add billing + outbox outcome mapping here.
//! - In particular, `failed + orphan_timeout` MUST map to outbox outcome="aborted",
//!   `settlement_method="estimated"` with deterministic formula and
//!   `minimal_generation_floor_applied`, and it MUST be emitted only by the CAS winner.
//! - This should be implemented via a transactional outbox enqueue in the same DB tx.

use modkit_db::secure::DBRunner;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::{
    CasCompleteParams, CasTerminalParams, InsertAssistantMessageParams, MessageRepository,
    TurnRepository,
};
use crate::infra::db::entity::chat_turn::TurnState;

// ────────────────────────────────────────────────────────────────────────────
// Parameter structs
// ────────────────────────────────────────────────────────────────────────────

/// Parameters for CAS-finalizing a completed/incomplete turn.
#[domain_model]
pub struct CompletedFinalizeParams {
    pub turn_id: Uuid,
    pub message_id: Uuid,
    pub tenant_id: Uuid,
    pub chat_id: Uuid,
    pub request_id: Uuid,
    pub text: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub model: Option<String>,
    pub provider_response_id: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Core CAS finalization
// ────────────────────────────────────────────────────────────────────────────

/// CAS-finalize a turn to a terminal state (failed / cancelled).
///
/// Returns `true` if this caller won the CAS race (`rows_affected = 1`).
/// The loser (`rows_affected = 0`) must NOT perform settlement or outbox.
///
/// # Errors
///
/// Returns `DomainError` on DB failure.
pub async fn cas_finalize_terminal<TR, C>(
    turn_repo: &TR,
    runner: &C,
    scope: &AccessScope,
    turn_id: Uuid,
    state: TurnState,
    error_code: Option<String>,
    error_detail: Option<String>,
) -> Result<bool, DomainError>
where
    TR: TurnRepository,
    C: DBRunner,
{
    let rows = turn_repo
        .cas_update_state(
            runner,
            scope,
            CasTerminalParams {
                turn_id,
                state,
                error_code,
                error_detail,
            },
        )
        .await?;
    Ok(rows > 0)
}

/// CAS-finalize a completed/incomplete turn: insert assistant message then
/// CAS update turn to `completed`.
///
/// Returns `true` if this caller won the CAS race.
///
/// # Errors
///
/// Returns `DomainError` on DB failure (message insert or CAS update).
pub async fn cas_finalize_completed<TR, MR, C>(
    turn_repo: &TR,
    message_repo: &MR,
    runner: &C,
    scope: &AccessScope,
    params: CompletedFinalizeParams,
) -> Result<bool, DomainError>
where
    TR: TurnRepository,
    MR: MessageRepository,
    C: DBRunner,
{
    let msg = message_repo
        .insert_assistant_message(
            runner,
            scope,
            InsertAssistantMessageParams {
                id: params.message_id,
                tenant_id: params.tenant_id,
                chat_id: params.chat_id,
                request_id: params.request_id,
                content: params.text,
                input_tokens: params.input_tokens,
                output_tokens: params.output_tokens,
                model: params.model,
                provider_response_id: params.provider_response_id.clone(),
            },
        )
        .await?;

    let rows = turn_repo
        .cas_update_completed(
            runner,
            scope,
            CasCompleteParams {
                turn_id: params.turn_id,
                assistant_message_id: msg.id,
                provider_response_id: params.provider_response_id,
            },
        )
        .await?;
    Ok(rows > 0)
}

// ────────────────────────────────────────────────────────────────────────────
// Convenience wrappers that manage their own DB connection + logging
// (used by stream_service where fire-and-forget semantics are needed)
// ────────────────────────────────────────────────────────────────────────────

use super::DbProvider;

/// Fire-and-forget wrapper: gets a DB connection, calls
/// [`cas_finalize_terminal`], and logs the result.
#[allow(clippy::cognitive_complexity)]
pub async fn persist_finalize_terminal<TR: TurnRepository>(
    db: &DbProvider,
    turn_repo: &TR,
    scope: &AccessScope,
    turn_id: Uuid,
    state: TurnState,
    error_code: Option<String>,
    error_detail: Option<String>,
) {
    let conn = match db.conn() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, turn_id = %turn_id, "CAS finalize: failed to get DB connection");
            return;
        }
    };

    let state_label = format!("{state:?}");
    match cas_finalize_terminal(turn_repo, &conn, scope, turn_id, state, error_code, error_detail)
        .await
    {
        Ok(true) => {
            debug!(turn_id = %turn_id, state = %state_label, "CAS terminal: turn finalized");
        }
        Ok(false) => warn!(turn_id = %turn_id, "CAS terminal: lost race (0 rows)"),
        Err(e) => warn!(error = %e, turn_id = %turn_id, "CAS terminal: update failed"),
    }
}

/// Fire-and-forget wrapper: gets a DB connection, calls
/// [`cas_finalize_completed`], and logs the result.
#[allow(clippy::cognitive_complexity)]
pub async fn persist_finalize_completed<TR: TurnRepository, MR: MessageRepository>(
    db: &DbProvider,
    turn_repo: &TR,
    message_repo: &MR,
    scope: &AccessScope,
    params: CompletedFinalizeParams,
) {
    let conn = match db.conn() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, turn_id = %params.turn_id, "CAS finalize: failed to get DB connection");
            return;
        }
    };

    let turn_id = params.turn_id;
    match cas_finalize_completed(turn_repo, message_repo, &conn, scope, params).await {
        Ok(true) => debug!(turn_id = %turn_id, "CAS completed: turn finalized"),
        Ok(false) => warn!(turn_id = %turn_id, "CAS completed: lost race (0 rows)"),
        Err(e) => warn!(error = %e, turn_id = %turn_id, "CAS completed: finalize failed"),
    }
}
