use async_trait::async_trait;
use modkit_db::secure::DBRunner;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::entity::message::Model as MessageModel;

/// Parameters for inserting a user message.
#[domain_model]
pub struct InsertUserMessageParams {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub chat_id: Uuid,
    pub request_id: Uuid,
    pub content: String,
}

/// Parameters for inserting an assistant message.
#[domain_model]
pub struct InsertAssistantMessageParams {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub chat_id: Uuid,
    pub request_id: Uuid,
    pub content: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub model: Option<String>,
    pub provider_response_id: Option<String>,
}

/// Repository trait for message persistence operations.
#[async_trait]
#[allow(dead_code)]
pub trait MessageRepository: Send + Sync {
    /// INSERT a user message linked to a turn's `request_id`.
    async fn insert_user_message<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: InsertUserMessageParams,
    ) -> Result<MessageModel, DomainError>;

    /// INSERT an assistant message with usage data. Returns the message model
    /// (caller uses `model.id` to set `chat_turns.assistant_message_id`).
    async fn insert_assistant_message<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: InsertAssistantMessageParams,
    ) -> Result<MessageModel, DomainError>;

    /// SELECT messages for a turn by `(chat_id, request_id)` where not deleted.
    async fn find_by_chat_and_request_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<MessageModel>, DomainError>;

    /// Load all non-archived, non-deleted messages for a chat, ordered by `created_at ASC`.
    async fn find_non_archived_by_chat<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Vec<MessageModel>, DomainError>;

    /// Mark messages as archived up to (and including) the message identified
    /// by `up_to_message_id`. Only non-archived, non-deleted messages in the
    /// given chat are affected. Returns the number of rows updated.
    async fn mark_archived<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        up_to_message_id: Uuid,
    ) -> Result<u64, DomainError>;
}
