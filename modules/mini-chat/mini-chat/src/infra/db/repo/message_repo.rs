use async_trait::async_trait;
use modkit_db::secure::{DBRunner, SecureEntityExt, SecureUpdateExt, secure_insert};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::{InsertAssistantMessageParams, InsertUserMessageParams};
use crate::infra::db::entity::message::{
    ActiveModel, Column, Entity as MessageEntity, MessageRole, Model as MessageModel,
};

pub struct MessageRepository;

#[async_trait]
impl crate::domain::repos::MessageRepository for MessageRepository {
    async fn insert_user_message<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: InsertUserMessageParams,
    ) -> Result<MessageModel, DomainError> {
        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            chat_id: Set(params.chat_id),
            request_id: Set(Some(params.request_id)),
            role: Set(MessageRole::User),
            content: Set(params.content),
            content_type: Set("text".to_owned()),
            token_estimate: Set(0),
            provider_response_id: Set(None),
            request_kind: Set(Some("chat".to_owned())),
            features_used: Set(serde_json::json!([])),
            input_tokens: Set(0),
            output_tokens: Set(0),
            model: Set(None),
            is_archived: Set(false),
            created_at: Set(now),
            deleted_at: Set(None),
        };
        Ok(secure_insert::<MessageEntity>(am, scope, runner).await?)
    }

    async fn insert_assistant_message<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: InsertAssistantMessageParams,
    ) -> Result<MessageModel, DomainError> {
        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            chat_id: Set(params.chat_id),
            request_id: Set(Some(params.request_id)),
            role: Set(MessageRole::Assistant),
            content: Set(params.content),
            content_type: Set("text".to_owned()),
            token_estimate: Set(0),
            provider_response_id: Set(params.provider_response_id),
            request_kind: Set(Some("chat".to_owned())),
            features_used: Set(serde_json::json!([])),
            input_tokens: Set(params.input_tokens.unwrap_or(0)),
            output_tokens: Set(params.output_tokens.unwrap_or(0)),
            model: Set(params.model),
            is_archived: Set(false),
            created_at: Set(now),
            deleted_at: Set(None),
        };
        Ok(secure_insert::<MessageEntity>(am, scope, runner).await?)
    }

    async fn find_by_chat_and_request_id<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<MessageModel>, DomainError> {
        Ok(MessageEntity::find()
            .filter(
                Condition::all()
                    .add(Column::ChatId.eq(chat_id))
                    .add(Column::RequestId.eq(request_id))
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(scope)
            .order_by(Column::CreatedAt, Order::Asc)
            .all(runner)
            .await?)
    }

    async fn find_non_archived_by_chat<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
    ) -> Result<Vec<MessageModel>, DomainError> {
        Ok(MessageEntity::find()
            .filter(
                Condition::all()
                    .add(Column::ChatId.eq(chat_id))
                    .add(Column::IsArchived.eq(false))
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(scope)
            .order_by(Column::CreatedAt, Order::Asc)
            .all(runner)
            .await?)
    }

    async fn mark_archived<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        chat_id: Uuid,
        up_to_message_id: Uuid,
    ) -> Result<u64, DomainError> {
        // Resolve the cutoff timestamp from the anchor message.
        let cutoff_expr = Expr::cust_with_values(
            "(SELECT created_at FROM messages WHERE id = $1)",
            [sea_orm::Value::from(up_to_message_id)],
        );

        let res = MessageEntity::update_many()
            .col_expr(Column::IsArchived, Expr::value(true))
            .filter(
                Condition::all()
                    .add(Column::ChatId.eq(chat_id))
                    .add(Expr::col(Column::CreatedAt).lte(cutoff_expr))
                    .add(Column::IsArchived.eq(false))
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(scope)
            .exec(runner)
            .await?;

        Ok(res.rows_affected)
    }
}
