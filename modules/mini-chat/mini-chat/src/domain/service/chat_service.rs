use std::sync::Arc;

use crate::domain::models::{Chat, ChatDetail, ChatPatch, NewChat};
use authz_resolver_sdk::PolicyEnforcer;
use authz_resolver_sdk::pep::AccessRequest;
use modkit_macros::domain_model;
use modkit_odata::{ODataQuery, Page};
use modkit_security::{SecurityContext, pep_properties};
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::{ChatRepository, ModelResolver};

use super::{DbProvider, actions, resources};

/// Service handling chat CRUD operations.
#[domain_model]
pub struct ChatService<CR: ChatRepository> {
    db: Arc<DbProvider>,
    chat_repo: Arc<CR>,
    enforcer: PolicyEnforcer,
    model_resolver: Arc<dyn ModelResolver>,
}

impl<CR: ChatRepository> ChatService<CR> {
    pub(crate) fn new(
        db: Arc<DbProvider>,
        chat_repo: Arc<CR>,
        enforcer: PolicyEnforcer,
        model_resolver: Arc<dyn ModelResolver>,
    ) -> Self {
        Self {
            db,
            chat_repo,
            enforcer,
            model_resolver,
        }
    }

    /// Create a new chat.
    #[instrument(skip(self, ctx, new))]
    pub async fn create_chat(
        &self,
        ctx: &SecurityContext,
        new: NewChat,
    ) -> Result<ChatDetail, DomainError> {
        tracing::debug!("Creating chat");

        let conn = self.db.conn().map_err(DomainError::from)?;
        let tenant_id = ctx.subject_tenant_id();

        validate_title(new.title.as_deref())?;

        let scope = self
            .enforcer
            .access_scope_with(
                ctx,
                &resources::CHAT,
                actions::CREATE,
                None,
                &AccessRequest::new()
                    .resource_property(pep_properties::OWNER_TENANT_ID, tenant_id)
                    .resource_property(pep_properties::OWNER_ID, ctx.subject_id()),
            )
            .await?;

        let model = self
            .model_resolver
            .resolve_model(tenant_id, &new.model)
            .await?;

        let now = OffsetDateTime::now_utc();
        let id = Uuid::now_v7();

        let chat = Chat {
            id,
            tenant_id,
            user_id: ctx.subject_id(),
            model,
            title: new.title.map(|t| t.trim().to_owned()),
            is_temporary: new.is_temporary,
            created_at: now,
            updated_at: now,
        };

        let created = self.chat_repo.create(&conn, &scope, chat).await?;

        tracing::debug!(chat_id = %created.id, "Successfully created chat");
        Ok(ChatDetail {
            id: created.id,
            model: created.model,
            title: created.title,
            is_temporary: created.is_temporary,
            message_count: 0,
            created_at: created.created_at,
            updated_at: created.updated_at,
        })
    }

    /// Get a chat by ID.
    #[instrument(skip(self, ctx), fields(chat_id = %id))]
    pub async fn get_chat(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<ChatDetail, DomainError> {
        tracing::debug!("Getting chat by id");

        let conn = self.db.conn().map_err(DomainError::from)?;

        let scope = self
            .enforcer
            .access_scope(ctx, &resources::CHAT, actions::READ, Some(id))
            .await?;

        let chat = self
            .chat_repo
            .get(&conn, &scope, id)
            .await?
            .ok_or_else(|| DomainError::chat_not_found(id))?;

        let message_count = self.chat_repo.count_messages(&conn, &scope, id).await?;

        tracing::debug!("Successfully retrieved chat");
        Ok(Self::to_detail(chat, message_count))
    }

    /// List chats with cursor-based pagination.
    #[instrument(skip(self, ctx, query))]
    pub async fn list_chats(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ChatDetail>, DomainError> {
        tracing::debug!("Listing chats");

        let conn = self.db.conn().map_err(DomainError::from)?;

        let scope = self
            .enforcer
            .access_scope(ctx, &resources::CHAT, actions::LIST, None)
            .await?;

        let page = self.chat_repo.list_page(&conn, &scope, query).await?;

        // Batch count: single GROUP BY query for all chat IDs
        let chat_ids: Vec<Uuid> = page.items.iter().map(|c| c.id).collect();
        let counts = if chat_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            self.chat_repo
                .count_messages_batch(&conn, &scope, &chat_ids)
                .await?
        };

        let items: Vec<_> = page
            .items
            .into_iter()
            .map(|chat| {
                let count = counts.get(&chat.id).copied().unwrap_or(0);
                Self::to_detail(chat, count)
            })
            .collect();

        tracing::debug!("Successfully listed {} chats", items.len());
        Ok(Page {
            items,
            page_info: page.page_info,
        })
    }

    /// Update a chat title.
    #[instrument(skip(self, ctx, patch), fields(chat_id = %id))]
    pub async fn update_chat(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
        patch: ChatPatch,
    ) -> Result<ChatDetail, DomainError> {
        tracing::debug!("Updating chat title");

        // Validate title
        if let Some(Some(title)) = &patch.title {
            validate_title(Some(title.as_str()))?;
        }

        let conn = self.db.conn().map_err(DomainError::from)?;

        let scope = self
            .enforcer
            .access_scope(ctx, &resources::CHAT, actions::UPDATE, Some(id))
            .await?;

        let mut chat = self
            .chat_repo
            .get(&conn, &scope, id)
            .await?
            .ok_or_else(|| DomainError::chat_not_found(id))?;

        // Apply patch
        if let Some(title_opt) = patch.title {
            chat.title = title_opt.map(|t| t.trim().to_owned());
        }
        chat.updated_at = OffsetDateTime::now_utc();

        let updated = self.chat_repo.update(&conn, &scope, chat).await?;
        let message_count = self.chat_repo.count_messages(&conn, &scope, id).await?;

        tracing::debug!("Successfully updated chat title");
        Ok(Self::to_detail(updated, message_count))
    }

    /// Soft-delete a chat.
    #[instrument(skip(self, ctx), fields(chat_id = %id))]
    pub async fn delete_chat(&self, ctx: &SecurityContext, id: Uuid) -> Result<(), DomainError> {
        tracing::debug!("Deleting chat");

        let conn = self.db.conn().map_err(DomainError::from)?;

        let scope = self
            .enforcer
            .access_scope(ctx, &resources::CHAT, actions::DELETE, Some(id))
            .await?;

        let deleted = self.chat_repo.soft_delete(&conn, &scope, id).await?;
        if !deleted {
            return Err(DomainError::chat_not_found(id));
        }

        tracing::debug!("Successfully deleted chat");
        Ok(())
    }

    fn to_detail(chat: Chat, message_count: i64) -> ChatDetail {
        ChatDetail {
            id: chat.id,
            model: chat.model,
            title: chat.title,
            is_temporary: chat.is_temporary,
            message_count,
            created_at: chat.created_at,
            updated_at: chat.updated_at,
        }
    }
}

/// Validate an optional title string: must be non-empty, non-whitespace, <=255 chars.
fn validate_title(title: Option<&str>) -> Result<(), DomainError> {
    if let Some(t) = title {
        let trimmed = t.trim();
        if trimmed.is_empty() {
            return Err(DomainError::validation(
                "Title cannot be empty or whitespace-only",
            ));
        }
        if trimmed.chars().count() > 255 {
            return Err(DomainError::validation(
                "Title must be 255 characters or fewer",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "chat_service_test.rs"]
mod tests;
