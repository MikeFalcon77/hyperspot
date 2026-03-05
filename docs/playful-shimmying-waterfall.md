# Plan: Fix Mini-Chat Workers — Phase 1 (Compile + Idle Loop)

## Context
Three background workers (orphan_watchdog, cleanup_worker, thread_summary_worker) exist but don't compile due to missing repo methods, non-existent module references, duplicate imports, and moved-variable issues in `module.rs`. Goal: make all 3 compile and run as idle loops with proper leader election and cancellation. Business logic deferred to later phases.

## Phase 1: Fix Compilation (4 files)

### 1. `src/domain/ports/mod.rs` — Add `NoopOutbox`
- Add `pub struct NoopOutbox;` implementing `OutboxPort` (all methods return `Ok(())`)
- Referenced by `Workers::new()` in module.rs line 323

### 2. `src/module.rs` — Fix imports, macro, and wiring
- **Remove duplicate imports**: lines 12+15 (`CancellationToken`), lines 13+16 (`tracing`)
- **Remove duplicate** `capabilities = [db, rest, stateful]` (line 56)
- **Add imports**: `use crate::config::WorkersConfig;`, `use crate::domain::ports::NoopOutbox;`
- **Clone Arcs before `AppServices::new()`** (before line 220):
  ```
  db_for_workers, turn_repo_for_workers, chat_repo_for_workers,
  message_repo_for_workers, provider_resolver_for_workers, workers_config
  ```
- **Fix `Workers::new()` call** (lines 239-250): use the `_for_workers` clones

### 3. `src/infra/workers/orphan_watchdog.rs` — Stub scan logic
- Remove bad imports: `crate::domain::service::finalize` (doesn't exist), `TurnState` (unused), `AccessScope` (unused), `anyhow::Context` (unused)
- Replace `scan_and_finalize` body with stub: `debug!("orphan scan: no implementation yet (stub)"); Ok(())`
- Keep: struct, constructor, `run()` loop — all correct

### 4. `src/infra/workers/thread_summary_worker.rs` — Stub scan logic
- Remove unused imports: `FmtWrite`, `Context`, `SecurityContext`, `Uuid`, `UpsertThreadSummaryParams`, `MessageRole`, LLM request types
- Remove constants: `SYSTEM_SUBJECT_ID`, `SUMMARIZATION_PROMPT`
- Replace `scan_and_summarize` body with stub: `debug!("thread summary scan: no implementation yet (stub)"); Ok(())`
- Remove `summarize_chat` method and `build_user_prompt` function entirely
- Keep: struct (with all fields including `thread_summary_repo`), constructor, `run()` loop

### Files NOT changed
- `cleanup_worker.rs` — already a correct stub
- `metrics.rs` — already correct
- `leader/mod.rs` — already correct
- `config.rs` — all configs correct

### Guideline Compliance (`docs/pr-review/modkit-rust-review.md`)

**RUST-NO-001**: Excluded — placeholder logic is acceptable for phased implementation. Stub scan methods with TODO comments are expected.

**RUST-ASYNC-001**: Worker loops use `tokio::select! { biased; }` with cancellation checks — already correct.

**RUST-OBS-001**: Workers log start/stop at `info` level with config values — already correct.

**RUST-PANIC-001**: No `unwrap`/`expect` in any worker path — verified.

**RUST-ERR-001**: `anyhow::Context` used for all fallible operations in non-stub code.

**RUST-OWN-001**: Cloning Arcs for `Workers::new()` is justified — they're shared across worker instances.

## Expected Result
All 3 workers compile, initialize with leader election (NoopLeaderElector locally, K8sLeaseElector in k8s), run idle interval loops logging debug stubs, and exit cleanly on cancellation.

## Future Phases (per DESIGN.md)

### Phase 2: Orphan Watchdog
- Add `find_orphaned_turns()` to `TurnRepository` trait + infra impl (query: `state='running' AND started_at < now() - timeout`)
- Wire CAS finalization (via `FinalizationService` or direct CAS path)
- Wire real outbox integration (replace `NoopOutbox` with `InfraOutboxEnqueuer`)

### Phase 3: Thread Summary Worker
- Add `find_chats_needing_summary(msg_threshold, turn_threshold)` to `ChatRepository` trait + infra impl
- Add `find_non_compressed_by_chat(chat_id)` to `MessageRepository` trait + infra impl
- Add `mark_compressed(chat_id, up_to_message_id)` to `MessageRepository` trait + infra impl
- Restore LLM summarization call via `ProviderResolver` with `requester_type=system`

### Phase 4: Cleanup Worker
- Add `find_pending_cleanup()` to `ChatRepository`
- Add attachment cleanup repo methods (find_by_chat, mark_cleaned, increment_attempts)
- Wire OAGW cleanup calls (delete vector store/file); treat 404 as success
- Uses `SELECT ... FOR UPDATE SKIP LOCKED` (no leader election needed)

### Phase 5: Outbox Dispatcher
- 4th worker from design — currently handled by `modkit_db::outbox::Outbox` pipeline in init()
- Evaluate if a separate worker is still needed or if the existing pipeline suffices

## Verification
1. `cargo check -p mini-chat` — no compilation errors
2. `cargo test -p mini-chat` — existing tests pass
3. Manual: start the module locally, verify worker start/stop logs appear
