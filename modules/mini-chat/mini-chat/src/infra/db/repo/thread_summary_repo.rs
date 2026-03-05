use async_trait::async_trait;
use modkit_db::secure::{DBRunner, SecureEntityExt, SecureInsertExt, SecureOnConflict};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::UpsertThreadSummaryParams;
use crate::infra::db::entity::thread_summary::{
    ActiveModel, Column, Entity as ThreadSummaryEntity, Model as ThreadSummaryModel,
};

pub struct ThreadSummaryRepository;

#[async_trait]
impl crate::domain::repos::ThreadSummaryRepository for ThreadSummaryRepository {
    async fn get_by_chat_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Option<ThreadSummaryModel>, DomainError> {
        Ok(ThreadSummaryEntity::find()
            .filter(
                Condition::all().add(Column::ChatId.eq(chat_id)),
            )
            .secure()
            .scope_with(scope)
            .one(runner)
            .await?)
    }

    async fn upsert<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: UpsertThreadSummaryParams,
    ) -> Result<ThreadSummaryModel, DomainError> {
        let now = OffsetDateTime::now_utc();

        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            chat_id: Set(params.chat_id),
            summary_text: Set(params.summary_text.clone()),
            summarized_up_to: Set(params.summarized_up_to),
            token_estimate: Set(params.token_estimate),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let on_conflict = SecureOnConflict::<ThreadSummaryEntity>::columns([Column::ChatId])
            .value(Column::SummaryText, Expr::value(params.summary_text))?
            .value(
                Column::SummarizedUpTo,
                Expr::value(params.summarized_up_to),
            )?
            .value(Column::TokenEstimate, Expr::value(params.token_estimate))?
            .value(Column::UpdatedAt, Expr::value(now))?;

        ThreadSummaryEntity::insert(am)
            .secure()
            .scope_unchecked(scope)?
            .on_conflict(on_conflict)
            .exec(runner)
            .await?;

        // Return the (possibly updated) row.
        self.get_by_chat_id(runner, scope, params.chat_id)
            .await?
            .ok_or_else(|| {
                DomainError::internal("thread summary upsert succeeded but row not found")
            })
    }
}
