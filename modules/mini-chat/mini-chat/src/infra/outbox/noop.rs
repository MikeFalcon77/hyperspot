use modkit_db::secure::DBRunner;
use modkit_security::AccessScope;
use serde_json::Value;
use uuid::Uuid;

use crate::domain::ports::OutboxPort;

/// No-op outbox implementation for P1.
///
/// This is intentionally side-effect free and only exists to make call-sites explicit.
pub struct NoopOutbox;

impl OutboxPort for NoopOutbox {
    fn enqueue(
        &self,
        _runner: &dyn DBRunner,
        _scope: &AccessScope,
        _namespace: &'static str,
        _topic: &'static str,
        _tenant_id: Option<Uuid>,
        _dedupe_key: Option<String>,
        _payload: Value,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

