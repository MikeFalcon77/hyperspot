# Proposal: Social Authentication for ModKit

## Status

Proposed.

## Problem Statement

We need a concrete way to implement social authentication in ModKit, starting with providers such as GitHub and
potentially Google later.

The current platform architecture already gives us two important constraints:

- `AuthN Resolver` validates bearer tokens and produces `SecurityContext`
- `api-gateway` currently authenticates only through the `Authorization: Bearer ...` header

What is missing is the interactive login boundary:

- browser redirect to the social provider
- callback handling
- authorization-code exchange
- external identity lookup
- binding external identity to an internal platform subject
- issuing a runtime credential that ModKit can use on subsequent API calls

In Tyk terms, this missing piece is not a gateway concern. It is the broker concern that sits in front of external
identity providers and behind the platform gateway.

This proposal defines how to add that missing login boundary without overloading `AuthN Resolver` with social-login
responsibilities.

## Current State and Constraints

The current codebase behaves as follows:

- `AuthNResolverClient.authenticate(bearer_token)` validates a bearer token and returns `AuthenticationResult`
- `AuthN Resolver` is a module + plugin integration point for token validation
- `api-gateway` extracts bearer tokens from the `Authorization` header and passes them to `AuthN Resolver`
- `api-gateway` does not currently implement browser session or cookie-based authentication

This means social authentication cannot be implemented correctly by simply adding a GitHub plugin to `AuthN Resolver`.
GitHub login is not a runtime bearer-token validation problem. It is an interactive login problem.

## Key Architectural Decision

Social login must terminate at a dedicated login boundary, implemented as a ModKit `Login Service / Identity Broker`.

The boundary is:

- external IdP tokens stop at the Login Service
- the Login Service performs identity binding and token issuance
- `AuthN Resolver` validates only runtime credentials that the platform trusts for API access

For the current scope, we do not need multiple-plugin runtime token routing inside `AuthN Resolver`.

Instead, we need a dedicated module for interactive login, with provider-specific social plugins selected explicitly by
provider identifier such as `github` or `google`.

## Reference Analogy: Tyk Gateway and Tyk Identity Broker

This split mirrors the Tyk architecture: `api-gateway` is analogous to the Tyk Gateway (traffic enforcement),
`Login Service / Identity Broker` is analogous to the Tyk Identity Broker (interactive login, callback handling,
credential issuance). The useful reference point is the boundary, not the exact implementation.

The separation of concerns:

- `api-gateway` — traffic enforcement plane for normal API requests
- `Login Service / Identity Broker` — delegated identity plane for browser login, provider callbacks, and token handoff
- `AuthN Resolver` — runtime credential validation behind the gateway path

The gateway exposes broker routes but does not itself become the social-login orchestrator.

One difference from historical TIB: short-lived login transactions and one-time handoff state in ModKit should use
shared durable storage in multi-instance deployments, rather than in-memory profiles.

## Goals

- implement social login for ModKit with the correct architectural boundary
- support provider-specific logic through plugins at the login boundary
- keep `AuthN Resolver` focused on runtime token validation only
- avoid requiring session or cookie support in `api-gateway` for the initial implementation
- support issuing a platform runtime token that existing gateway/authn flow can consume
- make GitHub login the first concrete provider, while keeping the design open for additional providers later

## Non-Goals

- passing GitHub or Google bearer tokens into `AuthN Resolver`
- redesigning the core `AuthN Resolver` public API for social login
- implementing a full enterprise broker matrix in the first iteration
- defining every Rust type and REST payload in final form
- introducing browser cookie/session auth into `api-gateway` in the first iteration

## Proposed Solution Overview

Introduce a dedicated ModKit system module, referred to in this document as `Login Service`.

The `Login Service` is responsible for interactive authentication and identity brokering. It uses provider plugins for
provider-specific OAuth2/OIDC behavior, and it issues a platform runtime token after login succeeds.

At a high level:

1. the frontend starts login with a chosen provider such as `github`
2. `api-gateway` exposes a public broker-owned login-start route and forwards the request to the `Login Service`
3. the `Login Service` resolves the corresponding social plugin
4. the plugin builds the authorization request details for that provider
5. the `Login Service` returns an HTTP redirect response to the provider
6. the provider redirects the browser back through a public broker-owned callback route
7. the `Login Service` validates `state` and exchanges the authorization code through the plugin
8. the plugin fetches and normalizes the external identity
9. the `Login Service` binds that external identity to an internal subject and tenant
10. the `Login Service` creates a one-time frontend handoff result
11. the browser is redirected back to the frontend
12. the frontend calls a public broker-owned exchange route to obtain the platform runtime token
13. the frontend uses that runtime token in `Authorization: Bearer ...`
14. `api-gateway` and `AuthN Resolver` continue working as they do today for protected API traffic

## Proposed Module Boundaries

### Login Service

Core responsibilities:

- start login for a selected provider
- own the broker-facing public route family for login start, provider callback, and frontend token exchange
- resolve provider plugins by explicit provider key
- manage `state`, nonce, and PKCE-related flow state where applicable
- handle callback requests
- coordinate authorization-code exchange through provider plugins
- perform external-to-internal identity binding
- consult binding storage and an internal subject or user directory to resolve the platform subject and tenant to
  use for the session
- issue platform runtime credentials
- produce a frontend-consumable login completion result

### Social Provider Plugins

Provider plugins encapsulate provider-specific behavior such as:

- building the authorization URL and scopes
- exchanging authorization code for provider tokens
- fetching external user profile information
- normalizing the provider response into a common external identity shape

Provider plugins do not produce `SecurityContext` directly for the rest of the platform.

Their output is a normalized external identity that the `Login Service` can bind to a platform subject.

Social plugin instances should expose stable metadata sufficient for explicit provider selection, for example a
`provider_key` in plugin properties or another equivalent registry-visible identifier.

The `Login Service` should discover provider plugins through the standard ModKit GTS + scoped `ClientHub`
mechanisms and maintain an explicit `provider_key -> gts_instance_id` mapping. Request-time routing by provider key
is module-owned selection logic; `vendor + priority` alone is not sufficient when multiple social providers coexist
under the same login boundary.

Examples:

- `github`
- `google`

This is simpler than runtime token routing and better matches the actual problem.

## Minimal End-to-End Flow

The recommended first implementation is a browser-based authorization-code flow with a backend callback.

The endpoint model should stay simple and broker-centric. For the first iteration, we need three public endpoint
classes exposed through `api-gateway` and owned by the `Login Service`:

- a login-start endpoint class for choosing a provider and initiating redirect-based login
- a provider-callback endpoint class for receiving the authorization response from the external IdP
- a frontend-exchange endpoint class for redeeming a one-time handoff handle into a platform runtime token

Exact URI shapes can be finalized during implementation, but responsibility should stay stable: the gateway exposes
the routes, and the `Login Service` owns their semantics.

### Start Login

The frontend initiates login by choosing a provider.
The login start endpoint is public and returns an HTTP redirect response.

The `Login Service`:

- validates that the provider is enabled
- creates a short-lived login transaction with `state`
- persists the post-login return target and any broker-owned correlation data needed for callback completion
- creates PKCE material if the plugin declares that the provider flow requires it
- redirects the browser to the provider authorization endpoint

### Callback Handling

The provider redirects the browser back to the `Login Service` callback endpoint.
The callback endpoint is public and, on success, returns another HTTP redirect response back to the frontend handoff
location.

The `Login Service`:

- verifies the callback belongs to a valid login transaction
- validates `state`
- rejects expired or already-consumed transaction state before any provider token exchange
- calls the plugin to exchange `code` for provider tokens
- calls the plugin to fetch external identity

### Error Handling During Callback

If the provider returns an error (for example, the user denied consent), or if `state` validation fails, or if
identity binding fails (no binding and fail-closed), the `Login Service` should redirect the browser back to the
frontend with an error indicator in the query string (not the token). The frontend-exchange endpoint should return a
standard RFC 9457 Problem response when the handle is expired, already consumed, or otherwise invalid.

### Identity Binding

After the external identity is normalized, the `Login Service` resolves an internal identity.

That resolution should support these cases:

- an existing binding already exists
- the external identity matches an explicitly configured pre-provisioned rule backed only by verified provider
  attributes
- the external identity is valid but no binding exists yet

Matching on unverified email or other weak claims must not be treated as sufficient.

For the first iteration, fail-closed is the safest default:

- if no binding exists, reject login unless explicit onboarding logic is enabled

### Runtime Token Issuance

After a binding is found, the `Login Service` issues a platform runtime token.

The signing configuration and the matching `AuthN Resolver` validation path are part of the runtime-token strategy
described later in this document. The browser-to-frontend token handoff is described in `Frontend Handoff`.

## Proposed Data Model

The implementation will need a small amount of persistent platform data.

### Social Identity Binding

Conceptually, we need a binding record containing:

- provider key
- external subject identifier
- internal subject identifier
- internal home tenant identifier
- binding status
- audit timestamps

The pair `(provider_key, external_subject_id)` must be unique. One internal subject may have bindings from multiple
providers.

Optional metadata may include:

- external login name snapshot
- email snapshot
- display name snapshot

### Login Transaction State

We also need short-lived login transaction storage for:

- `state`
- provider key
- redirect target
- PKCE verifier if used
- creation and expiry timestamps

### Login Result Handle

If we use the recommended frontend handoff pattern, we also need short-lived storage for:

- one-time login result handle
- internal subject reference
- runtime token or runtime-token creation context
- consumed-at timestamp or equivalent one-time-use marker
- expiry timestamp

For multi-instance or production deployments, login transactions and login-result handles should live in shared
durable storage owned by the `Login Service` module, with module-scoped migrations. In-memory storage is acceptable
only for single-instance local development. Expired records must be rejected based on stored expiry regardless of
cleanup timing; optional cleanup can run as a lifecycle-managed background task.

## Frontend Handoff

Because `api-gateway` currently expects bearer tokens rather than browser sessions, the `Login Service` should hand
the login result back to the frontend in a way that avoids placing the final runtime JWT directly in the redirect
URL.

Recommended pattern:

1. callback success creates a short-lived one-time login result handle
2. the browser is redirected back to the frontend with that handle
3. the frontend exchanges the handle for the platform runtime token through a public broker-owned exchange endpoint
4. the frontend stores and uses the runtime token as `Authorization: Bearer ...`

The handle must be high-entropy, short-lived, stored server-side, and invalidated on first successful exchange.

This keeps long-lived credentials out of query strings while preserving the existing bearer-token gateway model.

## GitHub as the First Concrete Provider

GitHub is a good first provider because it makes the architecture distinction obvious.

For GitHub social login:

- the provider returns an OAuth authorization code
- the backend exchanges the code for a GitHub access token
- that access token is a GitHub credential, not a ModKit runtime token
- the backend uses that GitHub token to fetch user profile data
- the backend then issues its own platform runtime token after identity binding

The GitHub token must not be forwarded to `AuthN Resolver` as the credential for normal API calls.

Conceptually, the GitHub social plugin needs provider-specific logic for:

- authorization endpoint parameters
- token endpoint exchange
- calling GitHub user profile endpoints
- optional email retrieval when email is not present in the primary profile response

The platform-specific logic still remains outside the plugin:

- user binding
- tenant resolution
- platform role or scope assignment
- runtime token issuance

## Runtime Token Strategy

For the first iteration, the cleanest path is to standardize on a single platform runtime token format.

Recommended choice:

- platform-issued signed JWT

That gives the following shape:

- `Login Service` issues platform JWT
- `api-gateway` continues to extract bearer token from the `Authorization` header
- `AuthN Resolver` validates the platform JWT and produces `SecurityContext`
- `Login Service` defines the signing key source, issuer, audience, algorithm, and rotation story as part of its
  runtime configuration
- `AuthN Resolver` validates these platform JWTs using a runtime plugin; the existing reference design in
  `docs/arch/authorization/AUTHN_JWT_OIDC_PLUGIN.md` already covers JWT local validation via JWKS, claim mapping to
  `SecurityContext`, and trusted-issuer configuration, so it can serve as the validation path once implemented and
  configured for the platform issuer

This avoids two sources of complexity:

- no need for gateway session support
- no need for multi-plugin runtime token selection in the resolver

## Impact on Existing Modules

### AuthN Resolver

Expected impact is small.

- keep current responsibility intact
- continue to validate runtime bearer tokens only
- no social-provider callbacks or code exchange logic
- no need for multiple runtime plugin support for this task
- implement or configure a platform-token validation plugin for the token format issued by the `Login Service`; the
  reference design in `docs/arch/authorization/AUTHN_JWT_OIDC_PLUGIN.md` already covers this use case

### API Gateway

Expected impact is also small.

- expose the broker route family through the gateway as the default ModKit path
- mark login-start, provider-callback, and frontend-exchange routes as public
- support login-start and callback routes that return HTTP redirects
- forward broker route traffic to the `Login Service` without turning the gateway into the social-login state owner
- keep protected application routes on bearer-token auth as they are today

No session or cookie support is required for the first iteration.

### AuthZ Resolver and Domain Modules

No architectural change is required.

They continue to receive `SecurityContext` produced from the validated runtime token.

## Security Requirements

The first implementation should explicitly enforce the following:

- validate `state` on every callback
- use PKCE where the selected provider flow supports it
- keep client secrets only in server-side configuration
- never place the final runtime token in a query string
- never pass external provider tokens beyond the login boundary
- avoid logging authorization codes, provider access tokens, or runtime tokens
- issue short-lived runtime access tokens with explicit issuer and audience
- if pre-provisioned matching is enabled, use only verified provider attributes and deterministic matching rules
- make one-time login result handles high-entropy, short-lived, and invalid after first successful exchange
- use shared durable storage for login transactions and handoff handles in multi-instance deployments
- fail closed when binding is missing or ambiguous

If refresh tokens are introduced later, they should be treated as a separate design topic.

## Suggested Implementation Phases

### Phase 1: End-to-End MVP

- create the `Login Service` module and add public routes for login start, callback, and frontend handoff/exchange
- implement shared short-lived login transaction storage and secure one-time frontend handoff
- implement one concrete provider plugin, starting with GitHub
- for dev-mode token issuance, issue a token compatible with the existing `static-authn-plugin` or an equivalent
  stub so that the end-to-end flow is runnable without production signing infrastructure
- complete a constrained end-to-end flow for an existing or explicitly pre-provisioned subject so that browser login
  is actually runnable

### Phase 2: Binding and Runtime Token Path

- add durable social identity bindings and explicit matching rules
- issue a platform JWT with explicit signing configuration
- implement the JWT/OIDC validation plugin per the reference design in
  `docs/arch/authorization/AUTHN_JWT_OIDC_PLUGIN.md` and configure it for the platform issuer
- connect the issued token to the existing bearer-token flow in non-development mode

### Phase 3: Production Hardening

- add audit events and metrics
- define expiry cleanup for short-lived login state
- tighten error handling and operator logs
- add additional providers if needed

## Open Questions

These questions do not block the architectural direction, but they should be answered during implementation:

- which module owns the social identity binding storage
- which module or service owns the internal subject or user directory used for binding and tenant resolution
- whether onboarding without a pre-existing binding is allowed
- whether pre-provisioned matching is allowed and which verified provider claims are sufficient
- what exact claims the platform JWT should contain
- where the `Login Service` signing keys come from and how key rotation is handled
- how the `Login Service` signing configuration and the `AuthN Resolver` validation configuration share issuer,
  audience, and public key material (shared config section, JWKS endpoint, or static key pair)
- whether any target deployment can rely on in-memory login transaction state, or whether shared durable storage is
  required from the start
- what exact TTL, entropy, and one-time-consumption semantics the frontend handoff handle must enforce
- whether the `Login Service` is exposed through the embedded `api-gateway` by default and what a separate edge
  deployment would require

## Recommended Direction for the Current Task

For the concrete task of "social plugin auth in ModKit", the recommended path is:

- build a dedicated `Login Service / Identity Broker` module
- put GitHub social-login logic into a provider plugin for that module
- bind the external GitHub identity to an internal subject
- issue one platform JWT format
- keep `AuthN Resolver` focused on runtime token validation only
- avoid requiring session or cookie support in `api-gateway` for the initial implementation
- support issuing a platform runtime token that existing gateway/authn flow can consume
- make GitHub login the first concrete provider, while keeping the design open for additional providers later

This is the smallest solution that is architecturally correct and compatible with the current gateway/authn flow.

## Summary

The proposal is not to extend `AuthN Resolver` into a social-login engine.

The proposal is to add a separate `Login Service / Identity Broker` in ModKit and place provider-specific social-login
plugins there.

With that approach:

- social login is implemented at the correct boundary
- the split between `api-gateway` and `Login Service / Identity Broker` matches the proven gateway-plus-broker model
- GitHub and future providers fit naturally through explicit provider plugins
- `AuthN Resolver` remains a runtime token validator
- `api-gateway` can keep its current bearer-token model
- the first implementation can stay small and focused
