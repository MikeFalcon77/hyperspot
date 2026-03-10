use mini_chat_sdk::UsageEvent;
use modkit_db::secure::DBRunner;

use crate::domain::error::DomainError;

/// Domain-layer abstraction for enqueuing outbox events within a transaction.
///
/// The finalization service calls this trait to insert outbox rows atomically
/// alongside the CAS state transition and quota settlement. The infra layer
/// implements it by delegating to `modkit_db::outbox::Outbox::enqueue()`.
///
/// # Why a trait?
///
/// The `modkit_db::outbox::Outbox` API is partition-based and accepts raw
/// `Vec<u8>` payloads. Mini-Chat needs a domain-oriented interface that:
/// - Accepts a typed `UsageEvent` (from `mini-chat-sdk`; serialized by the implementation)
/// - Resolves the queue name and partition from tenant context
/// - Participates in the caller's transaction via `&dyn DBRunner`
/// - Returns domain errors, not infra-level `OutboxError`
///
/// # Payload type
///
/// Uses `UsageEvent` from `mini-chat-sdk` directly — the single canonical
/// representation of the usage outbox payload. No separate domain payload type
/// exists. The SDK crate is already a dependency of the domain layer.
///
/// # Implementation note
///
/// The infra implementation (`InfraOutboxEnqueuer`) holds an
/// `Arc<modkit_db::outbox::Outbox>` and calls `outbox.enqueue(runner, ...)`
/// within the finalization transaction. The `Outbox::flush()` notification
/// is sent after the transaction commits (by the finalization service).
#[async_trait::async_trait]
pub trait OutboxEnqueuer: Send + Sync {
    /// Enqueue a usage event within the caller's transaction.
    ///
    /// The implementation MUST:
    /// - Serialize `event` to `Vec<u8>` (JSON wire format)
    /// - Insert into the outbox table using the provided `runner` (transaction)
    /// - Use `queue = "mini-chat.usage_snapshot"` (or equivalent registered name)
    /// - Derive the partition from `event.tenant_id`
    ///
    /// Duplicate prevention is handled by the CAS guard in the finalization
    /// transaction — the outbox enqueue is only reached by the CAS winner.
    ///
    /// Returns `Ok(())` on success. Returns `Err` on database error.
    async fn enqueue_usage_event(
        &self,
        runner: &(dyn DBRunner + Sync),
        event: UsageEvent,
    ) -> Result<(), DomainError>;

    /// Notify the outbox sequencer that new events are available.
    ///
    /// Called after the transaction that contains `enqueue_usage_event` commits.
    /// Multiple flush calls coalesce — calling flush 10 times results in at most
    /// one sequencer wakeup.
    ///
    /// This is outbox-wide: it wakes the sequencer for ALL registered queues,
    /// so a single flush call suffices regardless of which queue was written to.
    fn flush(&self);
}
