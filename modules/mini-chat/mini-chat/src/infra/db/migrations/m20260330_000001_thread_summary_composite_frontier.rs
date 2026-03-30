use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => POSTGRES_UP,
            sea_orm::DatabaseBackend::Sqlite => SQLITE_UP,
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Migration("MySQL not supported for mini-chat".into()));
            }
        };

        conn.execute_unprepared(sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => POSTGRES_DOWN,
            sea_orm::DatabaseBackend::Sqlite => SQLITE_DOWN,
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Migration("MySQL not supported for mini-chat".into()));
            }
        };

        conn.execute_unprepared(sql).await?;
        Ok(())
    }
}

const POSTGRES_UP: &str = r"
ALTER TABLE thread_summaries
    RENAME COLUMN summarized_up_to TO summarized_up_to_message_id;

ALTER TABLE thread_summaries
    ADD COLUMN summarized_up_to_created_at TIMESTAMPTZ;

UPDATE thread_summaries
    SET summarized_up_to_created_at = '1970-01-01T00:00:00Z'
    WHERE summarized_up_to_created_at IS NULL;

ALTER TABLE thread_summaries
    ALTER COLUMN summarized_up_to_created_at SET NOT NULL;
";

const POSTGRES_DOWN: &str = r"
ALTER TABLE thread_summaries
    DROP COLUMN summarized_up_to_created_at;

ALTER TABLE thread_summaries
    RENAME COLUMN summarized_up_to_message_id TO summarized_up_to;
";

const SQLITE_UP: &str = r"
ALTER TABLE thread_summaries
    RENAME COLUMN summarized_up_to TO summarized_up_to_message_id;

ALTER TABLE thread_summaries
    ADD COLUMN summarized_up_to_created_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z';
";

const SQLITE_DOWN: &str = r"
ALTER TABLE thread_summaries
    DROP COLUMN summarized_up_to_created_at;

ALTER TABLE thread_summaries
    RENAME COLUMN summarized_up_to_message_id TO summarized_up_to;
";
