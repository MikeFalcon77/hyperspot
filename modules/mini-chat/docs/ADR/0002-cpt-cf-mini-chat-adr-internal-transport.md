---
status: accepted
date: 2026-02-12
---
# HTTP/SSE for Internal Transport Between llm_provider and OAGW

**ID**: `cpt-cf-mini-chat-adr-internal-transport`

## Context and Problem Statement

`llm_provider` (a library crate inside `chat_service`) communicates with the platform's Outbound API Gateway (OAGW) to reach OpenAI. Streaming responses (SSE tokens) flow back through this path. What transport protocol should be used for this internal link: HTTP with SSE (matching the external OpenAI protocol) or gRPC with server-side streaming?

## Decision Drivers

* OAGW already exposes HTTP endpoints — adding gRPC would require OAGW changes
* OpenAI Responses API returns SSE — protocol alignment reduces mapping complexity
* Cancellation must propagate quickly (hard cancel: close TCP connection)
* Team familiarity — the team has HTTP/SSE experience; gRPC would introduce new tooling
* P0 timeline — minimize new infrastructure

## Considered Options

* HTTP with SSE passthrough (match OpenAI protocol end-to-end)
* gRPC with server-side streaming

## Decision Outcome

Chosen option: "HTTP with SSE passthrough", because OAGW already speaks HTTP, OpenAI returns SSE, and adding gRPC would require OAGW changes and new infrastructure with no clear benefit for P0.

### Consequences

* Good, because no changes required to OAGW — it already proxies HTTP/SSE to OpenAI
* Good, because SSE events from OpenAI pass through without protocol translation (lower latency, simpler code)
* Good, because cancellation is straightforward — dropping the HTTP connection propagates through OAGW to OpenAI
* Good, because debugging is simpler — `curl` can inspect SSE streams end-to-end
* Bad, because SSE is text-based and less efficient than gRPC binary framing (negligible for chat token payloads)
* Bad, because HTTP/1.1 SSE uses one TCP connection per stream (acceptable at P0 scale; HTTP/2 multiplexing available if needed)

### Confirmation

* Code review: `llm_provider` uses `reqwest` HTTP client, not a gRPC client
* Integration test: verify SSE events flow from OpenAI through OAGW to `chat_service` without protocol conversion
* Cancellation test: verify HTTP connection abort propagates through OAGW within 200 ms

## Pros and Cons of the Options

### HTTP with SSE passthrough

`llm_provider` sends HTTP requests to OAGW's existing endpoints. OAGW forwards to OpenAI. SSE events flow back unchanged.

* Good, because zero OAGW changes — existing HTTP proxy works as-is
* Good, because end-to-end SSE means no serialization/deserialization at the OAGW boundary
* Good, because team already knows HTTP/SSE; no new tooling (protobuf compiler, gRPC libraries)
* Good, because connection-close cancellation works naturally
* Neutral, because SSE text framing is slightly less compact than protobuf (irrelevant for small chat tokens)
* Bad, because no built-in schema validation (mitigated by `llm_provider` parsing SSE events with typed structs)

### gRPC with server-side streaming

`llm_provider` calls OAGW via gRPC. OAGW translates between gRPC and OpenAI's HTTP/SSE.

* Good, because gRPC has typed schemas (`.proto`) and built-in cancellation semantics
* Good, because binary framing is more efficient (marginal for chat payloads)
* Good, because HTTP/2 multiplexing allows multiple streams over one connection
* Bad, because OAGW does not currently support gRPC — requires new endpoint development
* Bad, because protocol translation (SSE ↔ gRPC) adds complexity and potential for bugs
* Bad, because introduces protobuf toolchain dependency for `mini-chat`
* Bad, because gRPC debugging is harder than SSE (requires grpcurl or similar tools)

## Re-evaluation Criteria

Consider migrating to gRPC if:

* OAGW adopts gRPC as a standard internal protocol for all consumers
* Connection count becomes a bottleneck (hundreds of concurrent streams per instance)
* Other modules need typed streaming contracts with OAGW beyond simple SSE passthrough

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-mini-chat-component-llm-provider` — Defines transport between `llm_provider` and OAGW
* `cpt-cf-mini-chat-nfr-streaming-latency` — SSE passthrough minimizes protocol translation overhead
* `cpt-cf-mini-chat-seq-cancellation` — HTTP connection close provides hard cancel propagation
* `cpt-cf-mini-chat-constraint-no-buffering` — No protocol translation layer that could introduce buffering
