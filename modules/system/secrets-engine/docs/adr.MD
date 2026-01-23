
# ADR: Secret Storage Module Architecture (ModKit Gateway + Plugins)

- **Status:** Proposed
- **Date:** 2026-01-20
- **Decision Drivers:**
    - **Store/retrieve secrets per tenant** (minimal surface).
    - Run in different environments:
        - **Desktop/VM**: OS protected storage (macOS Keychain / Windows protected storage).
        - **Kubernetes**: existing **Credstore** service via REST.
    - Consumers talk to one API; backend is selected at runtime.
    - Consistent authz model (`read` vs `write`) regardless of backend.
    - Reuse/centralize OAuth/OIDC config and token handling where possible.

---

## Context

We are building a new secret storage module in Rust on **ModKit**.
In Kubernetes we already have **Credstore** (Go, REST). We only need a small subset of its functionality:

- `put` secret (create/update)
- `get` secret
- optionally `delete` secret

Tenant scoping comes from the request **SecurityContext**.
Credstore additionally expects `tenant_id` as a query parameter and requires OAuth2.

---

## Decision

### 1) Use ModKit “Gateway + Plugins” architecture for secret storage

Structure:

- **Gateway module** `secrets-gw`
    - Stable API for other modules via `ClientHub`.
    - Chooses a plugin at runtime.
    - Enforces read/write authorization.
- **Plugins** (backend adapters)
    - `os_protected_storage` (desktop/VM).
    - `credstore_rest` (Kubernetes, REST to Credstore).

This follows ModKit plugin isolation rules: consumers only depend on the gateway API, not plugins directly.

### 2) Provide a minimal API contract (no full Credstore feature parity)

In `secrets-sdk` define two traits:

- `SecretsGatewayClient` (public, used by other modules)
- `SecretsPluginClient` (implemented by plugins, called by gateway)

Operations:

- `get(ctx, key) -> Option<bytes>`
- `put(ctx, key, bytes) -> ()`
- `delete(ctx, key) -> ()` (optional but recommended)

Tenant ID is not passed explicitly; it is derived from `SecurityContext` (e.g. `ctx.tenant_id()`).

### 3) Enforce authorization in the gateway (not in plugins)

Authorization lives in `secrets-gw` (plugins stay policy-free).
We enforce it twice:

- **Perimeter (REST API):** each secured endpoint uses `require_auth(resource, action)` before calling the domain/service.
- **Defense-in-depth (Gateway domain/service):** the gateway service also validates the required `resource:action` permission in `SecurityContext` for every operation. This protects non-REST (ClientHub) callers and prevents bypasses due to wiring/route configuration mistakes.

- `get` requires permission `secrets:read` (enforced at REST perimeter via `require_auth("secrets", "read")`)
- `put/delete` require permission `secrets:write` (enforced at REST perimeter via `require_auth("secrets", "write")`)

Plugins are “storage adapters” and must not implement policy decisions to avoid inconsistent behavior across backends.

### 4) Credstore integration: use `tenant_id` query parameter only

The `credstore_rest` plugin will always call Credstore with:

- `tenant_id=<tenant>` in query parameters
- no reliance on gateway headers like `X-Apigw-Tenant-Id`

### 5) Credstore key mapping: deterministic ExternalID derived from `{tenant}:{key}`

To avoid keeping a local mapping database and to achieve idempotency, we will map our `(tenant_id, key)` pair to a Credstore **ExternalID**.

Recommended mapping:

- `raw = "{tenant_id}:{key}"`
- `escaped = base64url_no_pad(raw)`
- `external_id = "{escaped}@secret"`

This avoids problematic characters in URL path and aligns with Credstore’s “InternalID or ExternalID” addressing.

### 6) Credstore REST operations used

Credstore endpoints used:

- **Read secret**
    - `GET /credentials/{external_id}?tenant_id=<tenant>&include_secret=true`
    - `404` -> return `None`
- **Write secret**
    - Preferred flow:
        - `PUT /credentials/{external_id}/identity_and_secret?tenant_id=<tenant>`
        - If `404`: `POST /credentials?tenant_id=<tenant>` (body includes `id=external_id`, `secret=<base64>`) then retry `PUT` to ensure overwrite semantics
- **Delete secret** (if supported by our module API)
    - `DELETE /credentials/{external_id}?tenant_id=<tenant>`

### 7) OAuth/OIDC configuration and token acquisition

Credstore auth uses **client credentials** (service-to-service).

- `issuer_url` is **global configuration**.
- Token acquisition/caching should be centralized (shared `oauth_token_provider` in `ClientHub`).
- `credstore_rest` stores only:
    - `client_id`, `client_secret` (optionally separate RO/RW)
    - `scopes`
    - `base_url`
    - timeouts/retries

Optionally, we will support two separate client credentials:
- **RO** for `get`
- **RW** for `put/delete`

This allows least-privilege deployments.

---

## Alternatives Considered

### A) Store local mapping key->uuid (InternalID) for Credstore
- **Rejected**: introduces additional state/storage requirements and complicates recovery/migrations.

### B) Implement full Credstore API in the new service
- **Rejected**: out of scope; we only need store/retrieve per-tenant secrets.

---

## Consequences

### Positive
- **Backend-agnostic consumers**: stable API via gateway, switch backend by config.
- **Consistent security model**: module-level read/write authorization enforced once.
- **Minimal surface area**: reduces maintenance and attack surface.
- **Idempotent, stateless mapping** to Credstore using ExternalID (no local DB required).
- **Centralized auth config**: global issuer URL and shared token caching.

### Negative / Tradeoffs
- ExternalID format must remain stable across versions to avoid breaking lookups.
- If Credstore has stricter validation for ExternalID content, we must ensure encoding conforms.
- Two-step write flow (PUT then POST then PUT) adds complexity (but improves performance for updates).

---

## Implementation Notes (Non-Normative)

- Plugin selection: gateway picks by config `vendor` and/or priority via types-registry.
- Keep key normalization/encoding shared so both backends behave the same.
- Error mapping:
    - 404 -> `None`
    - 401/403 -> permission error
    - other 5xx/timeouts -> retryable/internal error

---

## Next Steps

- Define `secrets-sdk` with gateway/plugin traits and error types.
- Implement `secrets-gw` module:
    - policy enforcement (read/write)
    - plugin resolution (vendor config)
- Implement plugins:
    - `os_protected_storage`
    - `credstore_rest`
- Implement shared `oauth_token_provider` (or equivalent shared component) using global `issuer_url`.

---

## Status

- Ready for review.