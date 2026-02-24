# ADR-0026: CyberFabric Plugin System for Backend Integration

**Date**: 2026-02-23

**Status**: accepted — supersedes ADR-0006 (Synchronous HTTP Webhooks with Streaming)

**ID**: `cpt-chat-engine-adr-plugin-backend-integration`

## Context and Problem Statement

ADR-0006 established HTTP webhooks as the integration mechanism between Chat Engine and message-processing backends. While HTTP webhooks work, they introduce significant operational complexity that must be re-implemented by every Chat Engine deployment:

- **Authentication**: Backend must validate incoming webhook requests (HMAC, JWT, mutual TLS)
- **Retry logic**: Chat Engine must implement exponential backoff with per-backend configuration
- **Circuit breaker**: Per-session-type circuit state to isolate failing backends (ADR-0011)
- **Throttling**: Rate limiting to protect backends from overload
- **Timeout management**: Per-backend timeouts with config storage (ADR-0013)
- **External network call**: Even co-located backends require an HTTP round-trip with serialization overhead

In practice, most backends are **co-located modules** within the same CyberFabric server process. Treating them as external HTTP services adds unnecessary complexity and latency. CyberFabric already provides the **CyberFabric ModKit Gateway + Plugin pattern** that solves all of these concerns at the framework level.

## Decision Drivers

* Eliminate webhook infrastructure complexity (auth, retry, circuit breaker, throttling) from Chat Engine itself
* Enable zero-overhead in-process calls for co-located backend modules
* Leverage existing CyberFabric plugin discovery (`types-registry` + `ClientHub`)
* Allow plugin vendors to implement external webhooks internally if needed — without Chat Engine knowing or caring
* Align with the established architectural pattern used across CyberFabric
* Simplify session type configuration (no `webhook_url` needed for native plugins)

## Considered Options

* **Option 1: HTTP webhooks (current)** — Chat Engine makes external HTTP POST to `webhook_url` stored per session type; handles auth, retry, circuit breaker itself
* **Option 2: CyberFabric Plugin System** — Chat Engine acts as a Gateway module; backends register as Plugin modules via `types-registry`; Chat Engine calls them through `ClientHub`
* **Option 3: Hybrid** — Native plugin interface as primary; HTTP webhook adapter plugin available for external backends

## Decision Outcome

Chosen option: **Option 3 (Hybrid)**, with Plugin System as the primary interface.

Chat Engine becomes a **Gateway module** that calls backend implementations via `dyn ChatEngineBackendPlugin`. A first-party **`chat-engine-webhook-adapter`** plugin wraps any external HTTP backend, so webhook-based backends remain supported — but the complexity of auth, retry, circuit breaker, and throttling is moved into the adapter plugin, not Chat Engine core.

On each API call (message send, session create, etc.) Chat Engine resolves the session type's `plugin_instance_id` to a `dyn ChatEngineBackendPlugin` via `ClientHub`, then calls the appropriate plugin method which streams response chunks back. Backend plugins (LLM, RAG, webhook adapter, etc.) each independently implement the same trait and register with `types-registry` at startup.

### Consequences

* Good, because Chat Engine core has zero authentication, retry, or circuit breaker code
* Good, because co-located plugins have zero HTTP overhead (direct Rust trait call)
* Good, because plugin vendors have full control over resilience strategy for external backends
* Good, because existing webhook-based backends continue to work via the adapter plugin
* Good, because capability declaration is type-safe (Rust trait, validated at compile time)
* Good, because plugin discovery uses the same `types-registry` + GTS pattern as all other CyberFabric modules
* Good, because `SessionType.webhook_url` is replaced by a `plugin_instance_id` (GTS ID) — simpler, versioned
* Bad, because plugin backends must be included in the server build (no dynamic load at runtime without restart)
* Bad, because the webhook adapter adds a thin indirection layer for external backends
* Bad, because ADR-0011 (circuit breaker) and ADR-0013 (timeout) become plugin responsibilities, not Chat Engine's — existing deployments depending on these must migrate to the adapter

## Plugin API Contract

Chat Engine defines a `ChatEngineBackendPlugin` trait in the `chat-engine-sdk` crate. Plugin methods are: `on_session_created` (called on session creation, returns available capabilities), `on_message` (streams response chunks), `on_message_recreate` (streams regenerated response), `on_session_summary` (streams summary), and an optional `health_check`. Full trait and context struct definitions are in `chat-engine-sdk` and documented in DESIGN.md §3.3.2.

## N:1 Session Types → Plugin Relationship

Multiple session types can share the same `plugin_instance_id`. Each session type carries its own `meta` configuration bag that Chat Engine forwards to the plugin in every call context (`session_type_meta` field). This allows a single plugin instance to serve multiple differently-configured session types without code duplication — for example, a single LLM plugin serving separate session types for GPT-4o (files enabled), GPT-4o (files disabled), and GPT-4o-mini, each differing only in their `meta`.

The call context passed to every plugin method includes both `session_type_id` and `session_type_meta`, so plugins branch on configuration without needing to know the session type at registration time. See DESIGN.md Plugin Integration for details.

## Session Type Configuration Change

| Before (ADR-0006) | After (ADR-0026) |
|---|---|
| `session_type.webhook_url: String` | `session_type.plugin_instance_id: GtsPluginInstanceId` |
| `session_type.timeout_seconds: u32` | Timeout owned by the plugin (or adapter config) |
| Chat Engine manages circuit breaker state | Plugin/adapter manages circuit breaker state |

## Migration Path

1. Existing deployments using HTTP webhooks: deploy `chat-engine-webhook-adapter` plugin pointing to current `webhook_url`
2. Session types: replace `webhook_url` with `plugin_instance_id` of the adapter instance
3. New backends: implement `dyn ChatEngineBackendPlugin` directly

## Related Design Elements

**Actors**:
* `cpt-chat-engine-actor-backend-plugin` — replaces `cpt-chat-engine-actor-webhook-backend`

**Requirements**:
* `cpt-chat-engine-fr-send-message` — plugin call replaces webhook POST
* `cpt-chat-engine-fr-create-session` — plugin call replaces session.created event
* `cpt-chat-engine-fr-schema-extensibility` — plugin schema registration via GTS

**Superseded ADRs**:
* ADR-0006 (Webhook Protocol) — superseded by this ADR
* ADR-0011 (Circuit Breaker) — responsibility moved to plugin/adapter
* ADR-0013 (Timeout Configuration) — responsibility moved to plugin/adapter

**Related ADRs**:
* ADR-0003 (Streaming Architecture) — streaming model unchanged; plugin provides `ResponseStream`
* ADR-0010 (Stateless Scaling) — unchanged; plugin clients resolved per-request from `ClientHub`