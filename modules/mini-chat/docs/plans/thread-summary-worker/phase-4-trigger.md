# Phase 4: Trigger — Evaluation in Finalization Path + Outbox Enqueue

## Goal

Evaluate the thread summary trigger during turn finalization and, if the compression
threshold is exceeded, enqueue a durable thread-summary outbox message atomically within
the CAS finalization transaction.

## Current State

- `FinalizationService::try_finalize()` at `src/domain/service/finalization_service.rs:190-332`
  runs steps 1-6 (CAS, billing, quota, message persist, usage event, audit event) inside
  a single `db.transaction()`.
- The `FinalizationInput` (line 19-62) carries `reserve_tokens: i64` from preflight —
  this is the assembled request token estimate already computed.
- No trigger evaluation exists today.
- `OutboxEnqueuer` now has `enqueue_thread_summary` (Phase 2).
- `ThreadSummaryRepository::get_latest` now returns real data (Phase 3).
- `MessageRepository::find_latest_message` exists (Phase 3).

## Design Constraints

From DESIGN.md:
- Trigger MUST evaluate the assembled request/context token estimate (already computed as
  `reserve_tokens` in preflight).
- The compression threshold is `80%` of the effective input token budget:
  `token_budget = min(configured_max_input_tokens, model_context_window - reserved_output_tokens)`
- Durable scheduling MUST occur only in the same transaction that makes the causing turn durable.
- Thread summary generation MUST NOT block or modify the user-visible response path.
- Any summary produced is eligible only for subsequent turns.
- The trigger SHOULD fire only for `Completed` turns (no point summarizing for failed turns).
- The request path SHOULD avoid enqueueing a duplicate when the frontier is unchanged.

## Tasks

### 4.1 Add compression threshold to config

File: `src/config/background.rs`

Add to `ThreadSummaryWorkerConfig`:

```rust
/// Compression threshold as a percentage of the effective input token budget.
/// Summary is triggered when estimated assembled request tokens >= threshold.
/// Default: 80 (from DESIGN.md B.9.4).
pub compression_threshold_pct: u32,
```

Default: `80`. Range: `1-99`.

### 4.2 Carry token budget info in `FinalizationInput`

File: `src/domain/model/finalization.rs`

Add fields to `FinalizationInput` needed for trigger evaluation:

```rust
/// Context window size of the effective model (tokens).
pub context_window: u32,
/// Max output tokens applied after preflight.
pub max_output_tokens_applied_for_budget: i32,
```

These are already available in `FinalizationCtx` (from preflight). Wire them through.

File: `src/domain/service/stream_service/types.rs`

In `FinalizationCtx`, these fields already exist. Ensure they flow into `FinalizationInput`
at the point where `FinalizationInput` is assembled from `FinalizationCtx` + `StreamOutcome`.

### 4.3 Add trigger evaluation function

File: `src/domain/service/finalization_service.rs`

Pure function — no I/O:

```rust
/// Evaluate whether thread summary should be triggered.
///
/// Returns `true` if the estimated assembled request tokens exceed the
/// compression threshold percentage of the effective input token budget.
fn should_trigger_summary(
    reserve_tokens: i64,
    context_window: u32,
    max_output_tokens: i32,
    compression_threshold_pct: u32,
) -> bool {
    // token_budget = min(configured_max_input_tokens, context_window - reserved_output_tokens)
    // For P1, we use reserve_tokens as the assembled request estimate (includes all
    // context items), and context_window - max_output_tokens as the effective budget.
    let effective_budget = i64::from(context_window) - i64::from(max_output_tokens);
    if effective_budget <= 0 {
        return false;
    }
    let threshold = effective_budget * i64::from(compression_threshold_pct) / 100;
    reserve_tokens >= threshold
}
```

### 4.4 Wire trigger into finalization transaction

File: `src/domain/service/finalization_service.rs`

Inside `try_finalize()`, after step 6 (enqueue audit event, line ~324), add step 7:

```rust
// 7. Evaluate thread summary trigger (only on Completed turns)
if input.terminal_state == TurnState::Completed
    && summary_config.enabled
    && should_trigger_summary(
        input.reserve_tokens,
        input.context_window,
        input.max_output_tokens_applied_for_budget,
        summary_config.compression_threshold_pct,
    )
{
    // Load current frontier
    let current_summary = thread_summary_repo
        .get_latest(tx, &scope, input.chat_id)
        .await
        .map_err(to_db)?;

    let base_frontier = current_summary.as_ref().map(|s| &s.frontier);

    // Determine frozen target: the just-persisted assistant message, or
    // the latest message if no assistant message was persisted.
    let frozen_target = message_repo
        .find_latest_message(tx, input.chat_id)
        .await
        .map_err(to_db)?;

    if let Some(target) = frozen_target {
        // Dedupe check: don't enqueue if the frontier hasn't moved
        // (same base and same target as what would be computed).
        let should_enqueue = match base_frontier {
            Some(bf) => bf != &target,  // frontier must have advanced
            None => true,               // first summary always enqueue
        };

        if should_enqueue {
            let payload = ThreadSummaryTaskPayload {
                tenant_id: input.tenant_id,
                chat_id: input.chat_id,
                system_request_id: Uuid::new_v4(),
                system_task_type: "thread_summary_update".to_owned(),
                base_frontier_created_at: base_frontier.map(|f| f.created_at),
                base_frontier_message_id: base_frontier.map(|f| f.message_id),
                frozen_target_created_at: target.created_at,
                frozen_target_message_id: target.message_id,
            };

            outbox_enqueuer
                .enqueue_thread_summary(tx, payload)
                .await
                .map_err(to_db)?;

            metrics.record_thread_summary_trigger("scheduled");
        } else {
            metrics.record_thread_summary_trigger("not_needed");
        }
    }
}
```

### 4.5 Inject dependencies into `FinalizationService`

File: `src/domain/service/finalization_service.rs`

Add to the struct:

```rust
thread_summary_repo: Arc<dyn ThreadSummaryRepository>,
summary_config: ThreadSummaryWorkerConfig,
```

Update the constructor and all call sites that create `FinalizationService` (in `module.rs`
and test helpers).

### 4.6 Wire trigger data from stream service

File: `src/domain/service/stream_service/types.rs`

The `FinalizationCtx` struct already carries preflight data. Ensure `context_window` and
`max_output_tokens_applied` flow into `FinalizationInput` when it is built in
`provider_task.rs`.

File: `src/domain/service/stream_service/provider_task.rs`

At each call site where `FinalizationInput` is constructed from `FinalizationCtx` +
stream outcome, populate the new fields:

```rust
context_window: ctx.context_window,
max_output_tokens_applied_for_budget: ctx.max_output_tokens_applied,
```

## Open Questions

- **`reserve_tokens` as trigger signal**: `reserve_tokens = estimated_input_tokens + max_output_tokens`.
  The trigger should use `estimated_input_tokens` (the assembled request estimate without
  output reservation). Since `reserve_tokens - max_output_tokens_applied = estimated_input_tokens`,
  we can derive it. The pure function `should_trigger_summary` handles this.

- **Trigger for orphan-finalized turns**: Orphan finalization (`finalize_orphan_turn`) should
  NOT trigger summary — the orphan path has no context assembly and no accumulated text.
  No change needed since the orphan path uses a separate method that does not call step 7.

## Acceptance Criteria

- [ ] `should_trigger_summary` returns `true` when `estimated_input >= 80% of budget`
- [ ] `should_trigger_summary` returns `false` when below threshold
- [ ] Trigger only fires for `Completed` turns
- [ ] Outbox message enqueued atomically within the finalization transaction
- [ ] `system_request_id` is `Uuid::new_v4()` generated once at enqueue
- [ ] Dedupe: no enqueue when base frontier equals target (frontier hasn't moved)
- [ ] Trigger does NOT block the user-visible response path (all within existing tx)
- [ ] Metrics: `record_thread_summary_trigger("scheduled"|"not_needed")` emitted
- [ ] Existing finalization tests pass with summary trigger disabled or below threshold
- [ ] New test: turn completion above threshold enqueues thread summary payload
- [ ] New test: turn completion below threshold does not enqueue
- [ ] New test: failed turn does not trigger summary
