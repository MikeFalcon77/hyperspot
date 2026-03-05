use std::sync::Arc;

use crate::domain::models::{ChatPatch, NewChat};
use modkit_odata::ODataQuery;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::repo::chat_repo::ChatRepository as OrmChatRepository;

use super::ChatService;
use crate::domain::service::test_helpers::{
    inmem_db, mock_db_provider, mock_enforcer, mock_model_resolver, test_security_ctx,
    test_security_ctx_with_id,
};

// ── Test Helpers ──

fn build_service(db: modkit_db::Db) -> ChatService<OrmChatRepository> {
    let db = mock_db_provider(db);
    let chat_repo = Arc::new(OrmChatRepository::new(modkit_db::odata::LimitCfg {
        default: 20,
        max: 100,
    }));

    ChatService::new(db, chat_repo, mock_enforcer(), mock_model_resolver())
}

// ── Tests ──

#[tokio::test]
async fn create_chat_default_model() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let tenant_id = Uuid::new_v4();
    let ctx = test_security_ctx(tenant_id);

    let result = svc
        .create_chat(
            &ctx,
            NewChat {
                model: String::new(), // empty → default
                title: Some("Hello".to_owned()),
                is_temporary: false,
            },
        )
        .await;

    assert!(result.is_ok(), "create_chat failed: {result:?}");
    let detail = result.unwrap();
    assert_eq!(detail.model, "gpt-5.2"); // default model
    assert_eq!(detail.title.as_deref(), Some("Hello"));
    assert_eq!(detail.message_count, 0);
}

#[tokio::test]
async fn create_chat_explicit_valid_model() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let result = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: None,
                is_temporary: false,
            },
        )
        .await;

    assert!(result.is_ok(), "create_chat failed: {result:?}");
    assert_eq!(result.unwrap().model, "gpt-5.2");
}

#[tokio::test]
async fn create_chat_disabled_model_rejected() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let result = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5-mini".to_owned(),
                title: None,
                is_temporary: false,
            },
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, DomainError::InvalidModel { .. }),
        "Expected InvalidModel for disabled model, got: {err:?}"
    );
}

#[tokio::test]
async fn create_chat_empty_title_rejected() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let result = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some(String::new()),
                is_temporary: false,
            },
        )
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), DomainError::Validation { .. }),
        "Expected Validation error for empty title at create"
    );
}

#[tokio::test]
async fn create_chat_title_trimmed() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let result = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("  padded  ".to_owned()),
                is_temporary: false,
            },
        )
        .await;

    assert!(result.is_ok(), "create_chat failed: {result:?}");
    assert_eq!(result.unwrap().title.as_deref(), Some("padded"));
}

#[tokio::test]
async fn create_chat_invalid_model() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let result = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "nonexistent-model".to_owned(),
                title: None,
                is_temporary: false,
            },
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, DomainError::InvalidModel { .. }),
        "Expected InvalidModel, got: {err:?}"
    );
}

#[tokio::test]
async fn get_chat_happy_path() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    // Create first
    let created = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("Test".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    // Get
    let fetched = svc.get_chat(&ctx, created.id).await.expect("get failed");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.title.as_deref(), Some("Test"));
}

#[tokio::test]
async fn get_chat_not_found() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let result = svc.get_chat(&ctx, Uuid::new_v4()).await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), DomainError::ChatNotFound { .. }),
        "Expected ChatNotFound"
    );
}

#[tokio::test]
async fn update_chat_title_happy_path() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let created = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("Old Title".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    let updated = svc
        .update_chat(
            &ctx,
            created.id,
            ChatPatch {
                title: Some(Some("New Title".to_owned())),
            },
        )
        .await
        .expect("update failed");

    assert_eq!(updated.title.as_deref(), Some("New Title"));
}

#[tokio::test]
async fn update_chat_title_empty_rejected() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let created = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("Title".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    let result = svc
        .update_chat(
            &ctx,
            created.id,
            ChatPatch {
                title: Some(Some(String::new())),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), DomainError::Validation { .. }),
        "Expected Validation error"
    );
}

#[tokio::test]
async fn update_chat_title_whitespace_only_rejected() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let created = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("Title".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    let result = svc
        .update_chat(
            &ctx,
            created.id,
            ChatPatch {
                title: Some(Some("   ".to_owned())),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), DomainError::Validation { .. }),
        "Expected Validation error"
    );
}

#[tokio::test]
async fn update_chat_title_too_long_rejected() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let created = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("Title".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    let long_title = "a".repeat(256);
    let result = svc
        .update_chat(
            &ctx,
            created.id,
            ChatPatch {
                title: Some(Some(long_title)),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), DomainError::Validation { .. }),
        "Expected Validation error"
    );
}

#[tokio::test]
async fn delete_chat_happy_path() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    let created = svc
        .create_chat(
            &ctx,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("To Delete".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    let result = svc.delete_chat(&ctx, created.id).await;
    assert!(result.is_ok(), "delete failed: {result:?}");

    // Should not be found after deletion
    let get_result = svc.get_chat(&ctx, created.id).await;
    assert!(matches!(
        get_result.unwrap_err(),
        DomainError::ChatNotFound { .. }
    ));
}

#[tokio::test]
async fn list_chats_returns_page() {
    let db = inmem_db().await;
    let svc = build_service(db);
    let ctx = test_security_ctx(Uuid::new_v4());

    // Create two chats
    svc.create_chat(
        &ctx,
        NewChat {
            model: "gpt-5.2".to_owned(),
            title: Some("First".to_owned()),
            is_temporary: false,
        },
    )
    .await
    .expect("create 1 failed");

    svc.create_chat(
        &ctx,
        NewChat {
            model: "gpt-5.2".to_owned(),
            title: Some("Second".to_owned()),
            is_temporary: false,
        },
    )
    .await
    .expect("create 2 failed");

    let query = ODataQuery::default();
    let page = svc.list_chats(&ctx, &query).await.expect("list failed");

    assert_eq!(page.items.len(), 2);
    // Verify descending sort invariant (updated_at DESC, id DESC tiebreaker)
    assert!(
        page.items
            .windows(2)
            .all(|w| (w[0].updated_at, w[0].id) >= (w[1].updated_at, w[1].id)),
        "Expected items sorted by (updated_at, id) DESC"
    );
}

// ── Permission Denied Tests ──

#[tokio::test]
async fn list_chats_cross_tenant_returns_empty() {
    let db = inmem_db().await;
    let svc = build_service(db);

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let ctx_a = test_security_ctx(tenant_a);
    let ctx_b = test_security_ctx(tenant_b);

    // Tenant A creates a chat
    svc.create_chat(
        &ctx_a,
        NewChat {
            model: "gpt-5.2".to_owned(),
            title: Some("Tenant A chat".to_owned()),
            is_temporary: false,
        },
    )
    .await
    .expect("create failed");

    // Tenant B lists — should see nothing (owner_tenant_id constraint filters)
    let page = svc
        .list_chats(&ctx_b, &ODataQuery::default())
        .await
        .expect("list failed");
    assert_eq!(page.items.len(), 0, "Tenant B must not see Tenant A chats");
}

#[tokio::test]
async fn list_chats_cross_owner_returns_empty() {
    let db = inmem_db().await;
    let svc = build_service(db);

    let tenant_id = Uuid::new_v4();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let ctx_a = test_security_ctx_with_id(tenant_id, user_a);
    let ctx_b = test_security_ctx_with_id(tenant_id, user_b);

    // User A creates a chat
    svc.create_chat(
        &ctx_a,
        NewChat {
            model: "gpt-5.2".to_owned(),
            title: Some("User A chat".to_owned()),
            is_temporary: false,
        },
    )
    .await
    .expect("create failed");

    // User B (same tenant) lists — should see nothing (owner_id constraint filters)
    let page = svc
        .list_chats(&ctx_b, &ODataQuery::default())
        .await
        .expect("list failed");
    assert_eq!(page.items.len(), 0, "User B must not see User A chats");
}

#[tokio::test]
async fn get_chat_cross_tenant_not_found() {
    let db = inmem_db().await;
    let svc = build_service(db);

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let ctx_a = test_security_ctx(tenant_a);
    let ctx_b = test_security_ctx(tenant_b);

    let created = svc
        .create_chat(
            &ctx_a,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("Tenant A chat".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    // Tenant B tries to get Tenant A's chat — should fail
    let result = svc.get_chat(&ctx_b, created.id).await;
    assert!(result.is_err(), "Cross-tenant get must fail");
    assert!(
        matches!(result.unwrap_err(), DomainError::ChatNotFound { .. }),
        "Expected ChatNotFound for cross-tenant access"
    );
}

#[tokio::test]
async fn delete_chat_cross_owner_not_found() {
    let db = inmem_db().await;
    let svc = build_service(db);

    let tenant_id = Uuid::new_v4();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let ctx_a = test_security_ctx_with_id(tenant_id, user_a);
    let ctx_b = test_security_ctx_with_id(tenant_id, user_b);

    let created = svc
        .create_chat(
            &ctx_a,
            NewChat {
                model: "gpt-5.2".to_owned(),
                title: Some("User A chat".to_owned()),
                is_temporary: false,
            },
        )
        .await
        .expect("create failed");

    // User B (same tenant) tries to delete User A's chat — should fail
    let result = svc.delete_chat(&ctx_b, created.id).await;
    assert!(result.is_err(), "Cross-owner delete must fail");
    assert!(
        matches!(result.unwrap_err(), DomainError::ChatNotFound { .. }),
        "Expected ChatNotFound for cross-owner delete"
    );
}
