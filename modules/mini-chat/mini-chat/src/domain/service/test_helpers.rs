use std::sync::Arc;

use async_trait::async_trait;
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, PolicyEnforcer,
    constraints::{Constraint, EqPredicate, Predicate},
    models::{DenyReason, EvaluationRequest, EvaluationResponse, EvaluationResponseContext},
};
use modkit_db::{
    ConnectOpts, DBProvider, Db, connect_db, migration_runner::run_migrations_for_testing,
};
use modkit_security::{SecurityContext, pep_properties};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::ModelResolver;

// ── Mock AuthZ Resolver ──

pub struct MockAuthZResolver;

#[async_trait]
impl AuthZResolverClient for MockAuthZResolver {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        let subject_tenant_id = request
            .subject
            .properties
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let subject_id = request.subject.id;

        // Deny when resource tenant_id differs from subject tenant_id
        if let Some(res_tenant) = request
            .resource
            .properties
            .get(pep_properties::OWNER_TENANT_ID)
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            && subject_tenant_id.is_some_and(|st| st != res_tenant)
        {
            return Ok(EvaluationResponse {
                decision: false,
                context: EvaluationResponseContext {
                    deny_reason: Some(DenyReason {
                        error_code: "tenant_mismatch".to_owned(),
                        details: Some("subject tenant does not match resource tenant".to_owned()),
                    }),
                    ..Default::default()
                },
            });
        }

        // Deny when resource owner_id differs from subject id
        if let Some(res_owner) = request
            .resource
            .properties
            .get(pep_properties::OWNER_ID)
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            && res_owner != subject_id
        {
            return Ok(EvaluationResponse {
                decision: false,
                context: EvaluationResponseContext {
                    deny_reason: Some(DenyReason {
                        error_code: "owner_mismatch".to_owned(),
                        details: Some("subject id does not match resource owner".to_owned()),
                    }),
                    ..Default::default()
                },
            });
        }

        // Build constraints from subject identity
        if request.context.require_constraints {
            let mut predicates = Vec::new();

            if let Some(tid) = subject_tenant_id {
                predicates.push(Predicate::Eq(EqPredicate::new(
                    pep_properties::OWNER_TENANT_ID,
                    tid,
                )));
            }

            predicates.push(Predicate::Eq(EqPredicate::new(
                pep_properties::OWNER_ID,
                subject_id,
            )));

            let constraints = vec![Constraint { predicates }];

            Ok(EvaluationResponse {
                decision: true,
                context: EvaluationResponseContext {
                    constraints,
                    ..Default::default()
                },
            })
        } else {
            Ok(EvaluationResponse {
                decision: true,
                context: EvaluationResponseContext::default(),
            })
        }
    }
}

// ── Mock Model Resolver ──

pub struct MockModelResolver;

#[async_trait]
impl ModelResolver for MockModelResolver {
    async fn resolve_model(&self, _tenant_id: Uuid, model: &str) -> Result<String, DomainError> {
        let catalog = [("gpt-5.2", true), ("gpt-5-mini", false)];

        if model.is_empty() {
            // Return default model
            Ok("gpt-5.2".to_owned())
        } else if catalog.iter().any(|(id, enabled)| *id == model && *enabled) {
            Ok(model.to_owned())
        } else {
            Err(DomainError::invalid_model(model))
        }
    }
}

// ── Test Helpers ──

pub async fn inmem_db() -> Db {
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db("sqlite::memory:", opts)
        .await
        .expect("Failed to connect to in-memory database");

    run_migrations_for_testing(&db, crate::infra::db::migrations::Migrator::migrations())
        .await
        .expect("Failed to run migrations");

    db
}

pub fn test_security_ctx(tenant_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::new_v4())
        .subject_tenant_id(tenant_id)
        .build()
        .expect("failed to build SecurityContext")
}

pub fn test_security_ctx_with_id(tenant_id: Uuid, subject_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(subject_id)
        .subject_tenant_id(tenant_id)
        .build()
        .expect("failed to build SecurityContext")
}

pub fn mock_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(MockAuthZResolver);
    PolicyEnforcer::new(authz)
}

pub fn mock_model_resolver() -> Arc<dyn ModelResolver> {
    Arc::new(MockModelResolver)
}

pub fn mock_db_provider(db: Db) -> Arc<DBProvider<modkit_db::DbError>> {
    Arc::new(DBProvider::new(db))
}
