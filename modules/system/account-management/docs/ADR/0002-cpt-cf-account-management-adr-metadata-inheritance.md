---
status: accepted
date: 2026-04-03
decision-makers: Virtuozzo
---

# ADR-0002: Barrier-Aware Walk-Up Resolution for Tenant Metadata Inheritance


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Option 1: Walk-up resolution at read time](#option-1-walk-up-resolution-at-read-time)
  - [Option 2: Materialized inheritance](#option-2-materialized-inheritance)
  - [Option 3: Hybrid walk-up with LRU cache](#option-3-hybrid-walk-up-with-lru-cache)
- [Barrier Semantics](#barrier-semantics)
  - [Considered Options for Barrier Behavior](#considered-options-for-barrier-behavior)
  - [Barrier Decision Outcome](#barrier-decision-outcome)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-account-management-adr-metadata-inheritance`

## Context and Problem Statement

AM supports extensible tenant metadata with per-schema inheritance policies. When a metadata schema uses the `inherit` policy, a child tenant that has no value of its own should receive the nearest ancestor's value. Two questions must be answered:

1. **Resolution strategy**: Compute inherited values at read time by walking the hierarchy, or pre-compute (materialize) inherited values at write time so reads are always O(1)?
2. **Barrier semantics**: Should the walk-up resolution cross self-managed tenant barriers, or stop at the first self-managed boundary?

## Decision Drivers

* **Write amplification**: The tenant hierarchy can be up to 10 levels deep with 1K–100K tenants. A parent metadata change under a materialized model must cascade to all descendants that don't have an override — potentially thousands of rows per write.
* **Consistency window**: Materialized values can become stale if the cascade update fails partially or is eventually consistent. Walk-up resolution always returns the current source-of-truth.
* **Read latency**: Metadata resolution is not on the per-request hot path (tenant-context validation is ≤ 5ms via Tenant Resolver caching). Metadata reads are infrequent administrative operations — p95 latency tolerance is significantly higher.
* **Hierarchy depth bound**: The advisory depth threshold is 10 levels. An ancestor walk is bounded at O(10) single-row lookups on the indexed `parent_id` column — sub-millisecond per hop.
* **Implementation complexity**: Materialized inheritance requires cascade triggers or an async propagation job, orphan detection for partial failures, and careful ordering when multiple ancestors change concurrently. Walk-up resolution requires no additional infrastructure.
* **Isolation consistency**: Self-managed tenants are defined as independent administrative boundaries, not merely hidden nodes in UI traversal.
* **No hidden barrier bypass**: AM metadata resolution must not introduce an AM-local equivalent of `BarrierMode::Ignore`.

## Considered Options

1. **Walk-up resolution at read time** — on each `/resolved` request, walk the `parent_id` chain from the target tenant upward until a value is found or the root is reached.
2. **Materialized inheritance** — on each metadata write, cascade the value to all descendant tenants that don't have their own override. Reads always return the local row.
3. **Hybrid: walk-up with LRU cache** — walk-up resolution with an in-memory cache per tenant+kind, invalidated on metadata writes for the tenant and its ancestors.

## Decision Outcome

Chosen option: **Walk-up resolution at read time**, because the hierarchy depth is bounded (≤ 10 levels), metadata reads are infrequent administrative operations (not hot-path), and the implementation avoids write amplification and cascade consistency problems entirely.

The walk **stops at the first self-managed barrier** — a self-managed tenant with no own value resolves to `empty`, preserving the self-managed independence contract adopted by the PRD and DESIGN.

The hybrid caching option is a future optimization if `am_metadata_resolve_duration_seconds` p95 exceeds acceptable thresholds at scale. It does not change the core resolution algorithm — only adds a cache layer on top.

### Consequences

* For `inherit` schemas, the `/resolved` endpoint walks ancestors only until it encounters the first self-managed boundary; ancestors above that boundary are not consulted. For hierarchies with no self-managed barrier on the path, the walk continues to the root.
* A self-managed tenant with no own value for a metadata kind resolves to `empty`, just like a root tenant with no value.
* No cascade infrastructure is needed — metadata writes are single-row operations. Changing a parent's metadata does not trigger any descendant updates.
* The resolved value is always consistent with the current hierarchy state — no staleness window.
* For `override-only` schemas, resolution is always O(1) — no ancestor walk needed.
* **Termination guarantee**: The walk always terminates at the root tenant (`parent_id = NULL`) or a self-managed barrier, not at the advisory depth threshold. The advisory threshold (default: 10) is a creation-time warning/limit — it does not bound existing hierarchies. If a hierarchy is deeper than the threshold (allowed in non-strict mode), the walk still reaches the root or a barrier. If no ancestor in the accessible chain has a value for the requested kind, the endpoint returns empty (no value). The walk is O(actual_depth), not O(max_configured_depth).
* No AM path performing metadata resolution requires or simulates `BarrierMode::Ignore`.
* If read latency becomes a concern at scale, an LRU cache can be added without changing the resolution contract or storage model.

### Confirmation

* `am_metadata_resolve_duration_seconds` histogram tracks resolution latency by inheritance policy. The `inherit` policy should show bounded latency proportional to hierarchy depth.
* Integration tests verify that changing a parent's metadata is immediately reflected in child `/resolved` responses without any explicit propagation.
* Integration tests verify three barrier cases: own value, inherited ancestor value below any barrier, and `empty` when the nearest ancestor value is above a self-managed boundary.
* No cascade triggers, background jobs, or materialized inheritance columns exist in the `tenant_metadata` table schema.
* PRD and DESIGN both state that metadata inheritance stops at self-managed boundaries and reference this ADR.

## Pros and Cons of the Options

### Option 1: Walk-up resolution at read time

* Good, because no write amplification — metadata writes are single-row operations regardless of hierarchy size.
* Good, because always consistent — no stale materialized values or partial cascade failures.
* Good, because simple implementation — no cascade triggers, propagation jobs, or invalidation logic.
* Good, because hierarchy depth is bounded (≤ 10 levels), making the ancestor walk predictable and fast.
* Neutral, because each `inherit` resolution performs up to 10 DB lookups — acceptable for infrequent admin reads, not suitable for hot-path use.
* Bad, because read latency scales linearly with hierarchy depth (though bounded at ~10 hops).

### Option 2: Materialized inheritance

* Good, because reads are always O(1) — the local row contains the effective value.
* Bad, because a parent metadata change must cascade to all descendants without an override — potentially thousands of rows, causing write amplification.
* Bad, because partial cascade failures create an inconsistent state that is hard to detect and repair.
* Bad, because concurrent writes to ancestors at different levels require careful ordering to avoid lost updates.
* Bad, because implementation requires cascade triggers or an async propagation job, adding infrastructure complexity.

### Option 3: Hybrid walk-up with LRU cache

* Good, because combines O(1) cache hits for repeated reads with always-correct walk-up on cache miss.
* Good, because no write amplification — cache is a read-through layer, not a materialized store.
* Neutral, because cache invalidation on ancestor metadata changes requires descendant enumeration (bounded but non-trivial).
* Bad, because adds in-memory state that must be sized and monitored (`am_metadata_resolve_cache_hit_ratio`).
* Bad, because introduces a consistency window between cache writes and invalidation — acceptable for admin reads but must be documented.

This option is deferred as a future optimization. The walk-up resolution baseline must be measured first.

## Barrier Semantics

### Considered Options for Barrier Behavior

* **Stop the walk at the first self-managed barrier** — treat a self-managed tenant as the upper bound of the accessible inheritance chain.
* **Ignore self-managed barriers** — walk to the root even when the path crosses a self-managed tenant boundary.
* **Materialize barrier-truncated effective metadata** — pre-compute effective values after each metadata or hierarchy change, with barrier rules applied during propagation.

### Barrier Decision Outcome

Chosen option: **Stop the walk at the first self-managed barrier**, because it preserves the self-managed independence contract already adopted by the PRD and DESIGN while retaining the simplicity and consistency benefits of read-time walk-up resolution.

Ignoring barriers would maximize reuse of ancestor metadata but contradicts the documented self-managed isolation contract and creates an implicit barrier-bypass rule inside AM. Materializing barrier-truncated values would re-introduce the write amplification and propagation complexity that the walk-up resolution strategy intentionally avoids.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements:

* `cpt-cf-account-management-fr-tenant-metadata-schema` — Per-schema inheritance policy (`inherit` vs `override-only`) determines resolution behavior.
* `cpt-cf-account-management-fr-tenant-metadata-crud` — Child tenants override inherited metadata by writing their own value; no cascade needed.
* `cpt-cf-account-management-fr-tenant-metadata-api` — The resolution API walks the hierarchy for `inherit` schemas at read time, stopping at self-managed boundaries.
* `cpt-cf-account-management-nfr-barrier-enforcement` — Metadata resolution does not contradict the barrier independence contract.
* `cpt-cf-account-management-principle-barrier-as-data` — AM stores the barrier flag and uses it only for metadata inheritance termination, not for generalized access-control bypass.
