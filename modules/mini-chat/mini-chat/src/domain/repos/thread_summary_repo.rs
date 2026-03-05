use async_trait::async_trait;
use modkit_db::secure::DBRunner;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;

/// Domain model for a thread summary used in context assembly.
#[domain_model]
#[derive(Debug, Clone)]
pub struct ThreadSummaryModel {
    pub content: String,
    pub boundary_message_id: Uuid,
    pub boundary_created_at: OffsetDateTime,
}

/// Parameters for upserting a thread summary.
#[domain_model]
pub struct UpsertThreadSummaryParams {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub chat_id: Uuid,
    pub summary_text: String,
    pub summarized_up_to: Uuid,
    pub token_estimate: i32,
}

/// Repository trait for thread summary persistence operations.
#[async_trait]
pub trait ThreadSummaryRepository: Send + Sync {
    /// Fetch the latest thread summary for a chat.
    ///
    /// Returns `None` if no summary exists (graceful degradation for P1).
    async fn get_latest<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Option<ThreadSummaryModel>, DomainError>;

    /// Load the thread summary for a chat (0..1 relationship).
    async fn get_by_chat_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Option<ThreadSummaryModel>, DomainError>;

    /// Insert or update the thread summary for a chat.
    ///
    /// Uses `ON CONFLICT (chat_id) DO UPDATE` to enforce the 1:1 constraint.
    async fn upsert<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: UpsertThreadSummaryParams,
    ) -> Result<ThreadSummaryModel, DomainError>;
    
}
