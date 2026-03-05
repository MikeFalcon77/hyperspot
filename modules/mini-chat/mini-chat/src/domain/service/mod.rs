use std::sync::Arc;

use authz_resolver_sdk::pep::ResourceType;
use authz_resolver_sdk::{AuthZResolverClient, PolicyEnforcer};
use modkit_db::DBProvider;
use modkit_macros::domain_model;

use crate::config::StreamingConfig;
use crate::domain::repos::{
    AttachmentRepository, ChatRepository, MessageRepository, ModelPrefRepository, ModelResolver,
    QuotaUsageRepository, ReactionRepository, TurnRepository, VectorStoreRepository,
};
use crate::infra::llm::LlmProvider;

mod attachment_service;
mod chat_service;
pub(crate) mod finalize;
mod model_service;
mod quota_service;
mod reaction_service;
mod stream_service;
#[cfg(test)]
pub(crate) mod test_helpers;

pub(crate) use attachment_service::AttachmentService;
pub(crate) use chat_service::ChatService;
pub(crate) use model_service::ModelService;
pub(crate) use quota_service::QuotaService;
pub(crate) use reaction_service::ReactionService;
pub(crate) use stream_service::{StreamError, StreamService};

pub(crate) type DbProvider = DBProvider<modkit_db::DbError>;

/// Authorization resource type for mini-chat.
///
/// All sub-resources (message, turn, attachment, reaction) inherit
/// authorization from the chat level — there is a single GTS resource type.
/// TODO: discuss with the team about resource type GTS identifier.
#[allow(dead_code)]
pub(crate) mod resources {
    use super::ResourceType;
    use modkit_security::pep_properties;

    pub const CHAT: ResourceType = ResourceType {
        name: "gts.cf.core.ai_chat.chat.v1~cf.core.mini_chat.chat.v1",
        supported_properties: &[
            pep_properties::OWNER_TENANT_ID,
            pep_properties::OWNER_ID,
            pep_properties::RESOURCE_ID,
        ],
    };
}

#[allow(dead_code)]
pub(crate) mod actions {
    pub const CREATE: &str = "create";
    pub const READ: &str = "read";
    pub const LIST: &str = "list";
    pub const UPDATE: &str = "update";
    pub const DELETE: &str = "delete";
    pub const LIST_MESSAGES: &str = "list_messages";
    pub const SEND_MESSAGE: &str = "send_message";
    pub const READ_TURN: &str = "read_turn";
    pub const RETRY_TURN: &str = "retry_turn";
    pub const EDIT_TURN: &str = "edit_turn";
    pub const DELETE_TURN: &str = "delete_turn";
    pub const UPLOAD: &str = "upload";
    pub const READ_ATTACHMENT: &str = "read_attachment";
    pub const REACT: &str = "react";
    pub const DELETE_REACTION: &str = "delete_reaction";
}

/// All repository instances passed to `AppServices::new` as a single bundle.
#[domain_model]
pub(crate) struct Repositories<
    TR: TurnRepository,
    MR: MessageRepository,
    QR: QuotaUsageRepository,
    CR: ChatRepository,
> {
    pub(crate) chat: Arc<CR>,
    pub(crate) attachment: Arc<dyn AttachmentRepository>,
    pub(crate) message: Arc<MR>,
    pub(crate) quota: Arc<QR>,
    pub(crate) turn: Arc<TR>,
    pub(crate) reaction: Arc<dyn ReactionRepository>,
    pub(crate) model_pref: Arc<dyn ModelPrefRepository>,
    pub(crate) vector_store: Arc<dyn VectorStoreRepository>,
}

/// DI container — aggregates all domain services.
///
/// Created once during `Module::init` and shared with handlers via `Arc`.
/// Services acquire database connections internally via `DbProvider`;
/// handlers call service methods with business parameters only.
#[domain_model]
#[allow(dead_code)]
pub(crate) struct AppServices<
    TR: TurnRepository + 'static,
    MR: MessageRepository + 'static,
    QR: QuotaUsageRepository + 'static,
    CR: ChatRepository + 'static,
> {
    pub(crate) chats: ChatService<CR>,
    pub(crate) stream: StreamService<TR, MR, CR>,
    pub(crate) reactions: ReactionService<CR>,
    pub(crate) attachments: AttachmentService<CR>,
    pub(crate) models: ModelService,
    pub(crate) quota: QuotaService<QR>,
}

impl<
    TR: TurnRepository + 'static,
    MR: MessageRepository + 'static,
    QR: QuotaUsageRepository + 'static,
    CR: ChatRepository + 'static,
> AppServices<TR, MR, QR, CR>
{
    pub(crate) fn new(
        repos: &Repositories<TR, MR, QR, CR>,
        db: Arc<DbProvider>,
        authz: Arc<dyn AuthZResolverClient>,
        model_resolver: Arc<dyn ModelResolver>,
        llm: Arc<dyn LlmProvider>,
        streaming_config: StreamingConfig,
    ) -> Self {
        let enforcer = PolicyEnforcer::new(authz);

        Self {
            chats: ChatService::new(
                Arc::clone(&db),
                Arc::clone(&repos.chat),
                enforcer.clone(),
                model_resolver,
            ),
            stream: StreamService::new(
                Arc::clone(&db),
                Arc::clone(&repos.turn),
                Arc::clone(&repos.message),
                Arc::clone(&repos.chat),
                enforcer.clone(),
                llm,
                streaming_config,
            ),
            reactions: ReactionService::new(
                Arc::clone(&db),
                Arc::clone(&repos.reaction),
                Arc::clone(&repos.chat),
                enforcer.clone(),
            ),
            attachments: AttachmentService::new(
                Arc::clone(&db),
                Arc::clone(&repos.attachment),
                Arc::clone(&repos.chat),
                Arc::clone(&repos.vector_store),
                enforcer.clone(),
            ),
            models: ModelService::new(
                Arc::clone(&db),
                Arc::clone(&repos.model_pref),
                enforcer.clone(),
            ),
            quota: QuotaService::new(db, Arc::clone(&repos.quota), enforcer),
        }
    }
}
