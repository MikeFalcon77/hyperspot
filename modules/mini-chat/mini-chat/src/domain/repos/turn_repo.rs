use async_trait::async_trait;
use modkit_db::secure::DBRunner;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::entity::chat_turn::{Model as TurnModel, TurnState};

/// Parameters for creating a new turn.
#[domain_model]
pub struct CreateTurnParams {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub chat_id: Uuid,
    pub request_id: Uuid,
    pub requester_type: String,
    pub requester_user_id: Option<Uuid>,
    /// Preflight fields — NULL in P2, populated by P3 quota service.
    pub reserve_tokens: Option<i64>,
    pub max_output_tokens_applied: Option<i32>,
    pub reserved_credits_micro: Option<i64>,
    pub policy_version_applied: Option<i64>,
    pub effective_model: Option<String>,
    pub minimal_generation_floor_applied: Option<i32>,
}

/// Parameters for CAS update to completed state.
#[domain_model]
#[allow(clippy::struct_field_names)]
pub struct CasCompleteParams {
    pub turn_id: Uuid,
    pub assistant_message_id: Uuid,
    pub provider_response_id: Option<String>,
}

/// Parameters for CAS update to a terminal state (failed/cancelled).
#[domain_model]
pub struct CasTerminalParams {
    pub turn_id: Uuid,
    pub state: TurnState,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
}

/// Repository trait for turn persistence operations.
#[async_trait]
#[allow(dead_code)]
pub trait TurnRepository: Send + Sync {
    /// INSERT a new turn with `state = running`.
    async fn create_turn<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: CreateTurnParams,
    ) -> Result<TurnModel, DomainError>;

    /// SELECT by `(chat_id, request_id)` for idempotency check.
    async fn find_by_chat_and_request_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<TurnModel>, DomainError>;

    /// SELECT the running turn for a chat (state=running, `deleted_at` IS NULL).
    async fn find_running_by_chat_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Option<TurnModel>, DomainError>;

    /// CAS state transition to a terminal state.
    /// Returns `rows_affected` (0 = another finalizer won, 1 = success).
    async fn cas_update_state<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: CasTerminalParams,
    ) -> Result<u64, DomainError>;

    /// CAS transition to completed, setting `assistant_message_id` and
    /// `provider_response_id`.
    async fn cas_update_completed<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: CasCompleteParams,
    ) -> Result<u64, DomainError>;

    /// Soft-delete a turn, linking to a replacement `request_id`.
    async fn soft_delete<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        turn_id: Uuid,
        replaced_by_request_id: Option<Uuid>,
    ) -> Result<(), DomainError>;

    /// SELECT the most recent non-deleted turn for a chat.
    async fn find_latest_turn<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Option<TurnModel>, DomainError>;

    /// SELECT all `running` turns whose `started_at` is older than `timeout`.
    ///
    /// Used by the orphan watchdog to detect turns abandoned by crashed pods.
    async fn find_orphaned_turns<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        timeout: std::time::Duration,
    ) -> Result<Vec<TurnModel>, DomainError>;
}
