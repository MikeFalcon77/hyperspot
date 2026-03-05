use async_trait::async_trait;
use modkit_db::secure::DBRunner;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::entity::thread_summary::Model as ThreadSummaryModel;

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
