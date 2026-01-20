
# ADR: Secret Storage Module Architecture (ModKit Gateway + Plugins)

- **Status:** Proposed
- **Date:** 2026-01-20
- **Decision Drivers:**
    - Minimal functionality required: **store / retrieve secrets per tenant**.
    - Support multiple runtimes:
        - **Desktop/VM**: store secrets in OS protected storage (macOS Keychain / Windows protected storage).
        - **Kubernetes**: store secrets in the existing **Credentials Store (Credstore) Go service** via REST.
    - Keep consumers decoupled from storage backends and allow runtime selection.
    - Enforce **module-level authorization** (read vs write) consistently across backends.
    - Centralize OAuth/OIDC configuration and token management where possible.

---

## Context

We are implementing a new secret storage service in Rust using **ModKit**. The organization already has an existing Go service (**Credstore**) that stores credentials and secrets per tenant and exposes a RAML-described REST API.

We do **not** want to re-implement the full Credstore API. We only need a small subset:

- `put` secret (create/update)
- `get` secret
- optionally `delete` secret

Secrets must be scoped **per tenant**, where the tenant is derived from the request **SecurityContext**.

Credstore requires OAuth2 authentication and tenant scoping via `tenant_id` query parameter.

---

## Decision

### 1) Use ModKit “Gateway + Plugins” architecture for secret storage

We will implement:

- **Gateway module** `secrets-gw`
    - Exposes a stable public API to other modules via `ClientHub`.
    - Selects the appropriate plugin implementation at runtime.
    - Enforces authorization policies (read/write).
- **Plugin modules** implementing backend-specific storage:
    - `os_protected_storage` plugin for desktop/VM environments.
    - `credstore_rest` plugin for Kubernetes environments (REST to Credstore).

This follows ModKit plugin isolation rules: consumers only depend on the gateway API, not plugins directly.

### 2) Provide a minimal API contract (no full Credstore feature parity)

In `secrets-sdk` define two traits:

- `SecretsGatewayClient` (public, used by other modules)
- `SecretsPluginClient` (implemented by plugins, called by gateway)

Operations:

- `get(ctx, key) -> Option<bytes>`
- `put(ctx, key, bytes) -> ()`
- `delete(ctx, key) -> ()` (optional but recommended)

Tenant ID is **not** passed explicitly. It is derived from `SecurityContext` (e.g. `ctx.tenant_id()`).

### 3) Enforce authorization in the gateway (not in plugins)

We will enforce module-level authorization in `secrets-gw` using the request `SecurityContext`.

Authorization is enforced at two levels:

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

We will only use the following Credstore endpoints:

- **Read secret**
    - `GET /credentials/{external_id}?tenant_id=<tenant>&include_secret=true`
    - `404` -> return `None`
- **Write secret**
    - Preferred write flow (optimizes for 1 call on existing secret):
        - `PUT /credentials/{external_id}/identity_and_secret?tenant_id=<tenant>` (if 404 then create)
        - If `404`:
            - `POST /credentials?tenant_id=<tenant>` with body including `id=external_id` and `secret=<base64>`
            - retry the `PUT` to ensure overwrite semantics
- **Delete secret** (if supported by our module API)
    - `DELETE /credentials/{external_id}?tenant_id=<tenant>`

### 7) OAuth/OIDC configuration and token acquisition

We will use **client credentials** for service-to-service auth to Credstore.

- `issuer_url` (OIDC issuer) is considered **global configuration**.
- Token acquisition and caching should be centralized via a shared component (recommended):
    - A module/client like `oauth_token_provider` registered in `ClientHub`
    - Provides cached access tokens and refresh logic
- The `credstore_rest` plugin will depend on the shared token provider and store only:
    - `client_id`, `client_secret` (possibly separate RO/RW credentials)
    - required `scopes`
    - Credstore `base_url`
    - timeouts/retry settings

Optionally, we will support two separate client credentials:
- **RO** for `get`
- **RW** for `put/delete`

This allows least-privilege deployments.

---

## Alternatives Considered

### A) Directly calling Credstore from consumers (no gateway)
- **Rejected**: violates ModKit plugin isolation principles and couples all consumers to Credstore REST/auth details.

### B) Single implementation (no plugin system)
- **Rejected**: prevents runtime/environment-specific backends and complicates desktop support.

### C) Store local mapping key->uuid (InternalID) for Credstore
- **Rejected**: introduces additional state/storage requirements and complicates recovery/migrations.

### D) Implement full Credstore API in the new service
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
- Plugin architecture adds additional crates/modules and types-registry wiring.
- ExternalID format must remain stable across versions to avoid breaking lookups.
- If Credstore has stricter validation for ExternalID content, we must ensure encoding conforms.
- Two-step write flow (PUT then POST then PUT) adds complexity (but improves performance for updates).

---

## Implementation Notes (Non-Normative)

- Gateway selects plugin by config `vendor` and/or priority using types-registry.
- Both plugins should use the same key normalization/encoding logic to keep behavior consistent across environments.
- Add clear error mapping:
    - Credstore 404 -> `None`
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

- **ADR written** and ready for review.