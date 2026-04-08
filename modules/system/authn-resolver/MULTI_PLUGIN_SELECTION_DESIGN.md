# AuthN Resolver: Multi-Plugin Selection Draft Design

## Status

Proposed.

## Context

`AuthNResolverPluginSpecV1` currently carries no plugin-specific routing metadata in `properties`. The resolver selects
a single plugin instance for the configured `vendor` and reuses it for all `authenticate()` calls.

This works for the current single-plugin model, but it does not fit deployments where multiple authentication plugins
must coexist under the same vendor, for example:

- an OIDC/JWT plugin for Google-issued tokens
- a custom plugin for GitHub opaque tokens
- a platform broker plugin for first-party tokens

For the next iteration, backward compatibility is not required. The existing `AuthNResolverPluginSpecV1` may be changed
in place.

## Upstream Authentication Flow

The resolver does not participate in OAuth2 redirects, authorization code exchanges, or user-facing login flows. Those
concerns belong to the upstream layer (frontend + API Gateway or a dedicated login service).

A typical social login flow (e.g. Google, GitHub) looks like this:

1. the user clicks "Login via Google" in the application frontend
2. the frontend redirects the user to the provider's `/authorize` endpoint
3. the user authenticates with the provider
4. the provider redirects back to the application with an authorization `code`
5. the application backend exchanges the `code` for tokens at the provider's `/token` endpoint
6. the backend obtains a bearer token (JWT `id_token` for OIDC providers, opaque `access_token` for OAuth2-only
   providers like GitHub)
7. the backend includes this bearer token in subsequent API requests

The resolver enters the picture only at step 7, when an API request arrives with a bearer token in the `Authorization`
header. The resolver's job is to route the token to the correct plugin and return a validated `SecurityContext`.

This separation is important because different providers return different token types after the code exchange:

- OIDC providers (Google, Azure AD) return a JWT `id_token` that can be validated locally via JWKS
- OAuth2-only providers (GitHub) return an opaque `access_token` that requires a provider API call to validate

The resolver does not need to know these details. It classifies the token (JWT vs opaque), routes it to the correct
plugin based on metadata, and the plugin handles all provider-specific validation internally.

For in-process module-to-module calls within the same ModKit process, `SecurityContext` is propagated through the call
chain after the initial gateway-level authentication. Modules do not re-authenticate tokens internally.

## Goals

- allow multiple AuthN plugins to coexist for the same `vendor`
- make plugin selection deterministic per `authenticate()` request
- move plugin selection to declarative metadata stored in the plugin GTS instance
- keep token validation inside plugins, not in the resolver
- support efficient routing with caching

## Non-Goals
- defining plugin-internal validation rules
- defining exact Rust structs, enum variants, or schema syntax
- describing migration or backward compatibility strategy

## Design Overview

The resolver becomes a routing gateway instead of a single-plugin gateway.

Instead of selecting one plugin once and delegating all traffic to it, the resolver:

1. maintains a catalog of registered AuthN plugin instances for the configured `vendor`
2. inspects each incoming authentication request just enough to derive routing hints
3. selects the best matching plugin using metadata from `AuthNResolverPluginSpecV1`
4. delegates actual token validation to the selected plugin

The resolver must not treat routing hints as proof of authentication. Any token parsing done before dispatch is used
only to choose a plugin.

## Plugin Metadata

`AuthNResolverPluginSpecV1` should be extended so that `properties` describe routing capabilities.

At a high level, the metadata should answer these questions:

- which token kinds can this plugin handle
- which JWT issuers map to this plugin
- which opaque token hints map to this plugin
- whether this plugin can be used as an explicit or fallback route for client credentials

The metadata is intended for plugin selection only. It should not contain operational secrets, claim mapping rules, or
validation implementation details.

### Proposed GTS Type Shape

The updated `AuthNResolverPluginSpecV1` should remain a plugin properties payload under `BaseModkitPluginV1`, but its
`properties` section should become non-empty and carry routing metadata.

Conceptually, the shape should look like this:

```json
{
  "provider_kind": "oidc_jwt",
  "authenticate_routes": [
    {
      "kind": "jwt_issuer",
      "values": [
        "https://accounts.google.com"
      ]
    }
  ],
  "client_credentials_routes": []
}
```

At the design level, the GTS type should support these concepts:

- `provider_kind`
    - descriptive classification such as `oidc_jwt`, `oauth_opaque`, `brokered_platform`, `static`, `custom`
- `authenticate_routes`
    - declarative rules used during `authenticate()` selection
    - examples: `jwt_issuer`, `jwt_issuer_prefix`, `opaque_prefix`, `opaque_default`
- `client_credentials_routes`
    - declarative rules used during `exchange_client_credentials()` selection
    - examples: explicit route key, optional default route

This keeps the schema universal while preserving the main architectural rule: plugin metadata describes selection,
plugin code performs authentication.

### Metadata Categories

The exact field names can be decided later, but the metadata should cover the following categories:

- token kind support
    - JWT
    - opaque tokens
- JWT routing hints
    - exact issuer values
    - optional issuer prefixes or families
- opaque token routing hints
    - explicit prefixes or other cheap, local hints
    - optional default opaque handler role
- client credentials routing hints
    - explicit route keys
    - optional default route
- provider classification
    - descriptive provider kind for diagnostics and observability

### Example Plugin Instances

The following examples show how plugin instances would look conceptually when registered in the types registry.

#### Google Plugin Example

```json
{
  "id": "gts.x.core.modkit.plugin.v1~hyperspot.authn.google.plugin.v1~",
  "vendor": "hyperspot",
  "priority": 100,
  "properties": {
    "provider_kind": "oidc_jwt",
    "authenticate_routes": [
      {
        "kind": "jwt_issuer",
        "values": [
          "https://accounts.google.com"
        ]
      }
    ],
    "client_credentials_routes": []
  }
}
```

This plugin is selected for JWT bearer tokens whose unverified issuer matches Google.

#### GitHub Plugin Example

```json
{
  "id": "gts.x.core.modkit.plugin.v1~hyperspot.authn.github.plugin.v1~",
  "vendor": "hyperspot",
  "priority": 110,
  "properties": {
    "provider_kind": "oauth_opaque",
    "authenticate_routes": [
      {
        "kind": "opaque_prefix",
        "values": [
          "gho_",
          "ghu_",
          "github_pat_"
        ]
      }
    ],
    "client_credentials_routes": []
  }
}
```

This plugin is selected for opaque bearer tokens that match known GitHub token families.

## Selection Model

Plugin selection happens for each `authenticate()` call.

### JWT Tokens

For JWT-like tokens, the resolver may inspect the token without trusting it and extract routing hints such as issuer.
Those hints are used only to identify candidate plugins.

The resolver then selects the best plugin using metadata matching rules. The chosen plugin performs full authentication.

### Opaque Tokens

For opaque tokens, the resolver cannot rely on issuer-based routing. Selection should therefore depend on explicit
metadata hints declared by plugins, such as token prefix families or an explicitly configured fallback role.

If no unambiguous route exists, authentication must fail closed.

### Client Credentials

`exchange_client_credentials()` cannot rely on token inspection because there is no incoming bearer token. The caller
already knows which provider its credentials belong to (it obtained `client_id` and `client_secret` from its own
configuration alongside the provider identity), so routing must use an explicit hint from the caller.

`ClientCredentialsRequest` should be extended with an optional `provider` field:

- when `provider` is set, the resolver matches it against `client_credentials_routes` in plugin metadata
- when `provider` is not set, the resolver selects the single plugin that declares a `default` client-credentials
  route for the configured vendor; if zero or more than one plugin declares a default, the request fails closed

This keeps the resolver stateless with respect to `client_id` values (which are provider-specific and opaque to the
resolver) while giving callers a deterministic routing mechanism.

Note: adding an `Option<String>` field to `ClientCredentialsRequest` is a struct-level change, not a trait signature
change. Existing callers that do not set the field get the default-route behavior.

## Selection Flow Relative to the Current Resolver

The current `authn-resolver` service keeps a single `GtsPluginSelector`, resolves one plugin instance through
`resolve_plugin()`, and reuses that plugin for all authentication requests.

In the proposed model, the current shape evolves as follows:

- `resolve_plugin()` becomes catalog-oriented rather than single-instance oriented
- the resolver still queries the types registry by `AuthNResolverPluginSpecV1::gts_schema_id()` and `vendor`
- instead of calling `choose_plugin_instance()` once and caching one `gts_id`, the resolver loads candidate plugin
  instances for the configured `vendor`
- plugin dispatch happens per request based on the token and the candidate metadata

At a high level, `authenticate()` should behave like this:

1. load or reuse the cached plugin catalog for the configured `vendor`
2. inspect the incoming bearer token just enough to derive routing hints
3. filter candidate plugins by `authenticate_routes`
4. resolve to exactly one plugin; if more than one candidate matches, fail closed (configuration error)
5. obtain the scoped plugin client from `ClientHub`
6. call `plugin.authenticate(bearer_token)` on the selected plugin

The same principle applies to `exchange_client_credentials()`, but selection must use explicit routing metadata rather
than token inspection.

### Token Classification Heuristic

Before applying routing rules, the resolver must classify the incoming bearer token as JWT-like or opaque. The
heuristic should be cheap and deterministic:

1. split the token string by `.`
2. if the token contains exactly three segments and the first segment is valid base64url-encoded JSON containing an
   `"alg"` field, classify the token as JWT-like
3. otherwise, classify the token as opaque

If the first segment looks like base64url but fails to parse as JSON, the token is classified as opaque (not an error).
This covers edge cases where an opaque token happens to contain `.` characters.

### Routing Rules

The resolver should follow these rules in order:

1. classify the bearer token as JWT-like or opaque using the heuristic above
2. for JWT-like tokens
    - decode the header and payload without signature verification
    - extract `iss` only as a routing hint
    - prefer exact `jwt_issuer` matches
    - then broader `jwt_issuer_prefix` matches; when multiple prefixes match, prefer the longest prefix
    - if the token was classified as JWT-like but the payload cannot be decoded or `iss` is missing, return
      `Unauthorized` immediately; do not fall through to opaque routing, because a structurally JWT-like token that
      fails to parse is malformed, not opaque
3. for opaque tokens
    - prefer explicit `opaque_prefix` matches; when multiple prefixes match, prefer the longest prefix
    - then `opaque_default` only if exactly one plugin declares it for the configured vendor
4. route matching must resolve to exactly one plugin; if more than one plugin matches the same route, this is a
   configuration error and the resolver must fail closed
5. if no candidate matches at all, return `Unauthorized`

Plugins do not compete by priority for the same route. Each route (issuer value, prefix, default role) must map to
exactly one plugin. The `priority` field in `BaseModkitPluginV1` is not used for routing tie-breaking in this design.

This keeps the proposed behavior close to the existing resolver architecture while replacing process-global
single-plugin selection with deterministic per-request routing.

## Multiple Plugins Per Vendor

Multiple plugins registered for the same `vendor` are supported by design.

The resolver should no longer cache a single plugin instance globally. Instead, it should resolve among all matching
plugins belonging to the configured vendor.

This allows combinations such as:

- one plugin for Google JWTs
- one plugin for GitHub opaque tokens
- one plugin for platform-issued first-party tokens

The resolver remains responsible only for choosing the plugin. Plugins remain responsible for authentication logic and
`SecurityContext` construction.

## Matching and Conflict Resolution

Selection must be deterministic and fail closed.

At a high level, matching should follow these principles:

- prefer exact matches over broad matches
- prefer explicit routing hints over fallback roles
- prefer longer prefix matches over shorter ones (longest-prefix-match)
- each route value (issuer, prefix, default role) must resolve to exactly one plugin
- if two or more plugins match the same route, treat this as a configuration error and fail closed

Example outcomes:

- a single exact issuer match -> dispatch to that plugin
- two plugins declare the same exact issuer -> fail closed (configuration error)
- two prefix matches of different lengths -> dispatch to the longest prefix match
- two prefix matches of the same length from different plugins -> fail closed (configuration error)
- no route match -> return `Unauthorized`

### Catalog-Level Validation

When building the routing index from the plugin catalog, the resolver should detect and report configuration conflicts
eagerly rather than waiting for a request to trigger them:

- if more than one plugin declares `opaque_default` for the same vendor, log an error and do not register any default;
  explicit `opaque_prefix` routes continue to work
- if two plugins declare the exact same `jwt_issuer` value, log an error; this is a hard conflict that will cause
  fail-closed behavior at request time, and operators must fix it by removing the duplicate
- if two plugins declare `opaque_prefix` or `jwt_issuer_prefix` values of the same length that overlap, log an error;
  longest-prefix-match only resolves conflicts when prefix lengths differ
- overlapping prefixes of different lengths are not a conflict because longest-prefix-match provides deterministic
  resolution; no error or warning is needed

## Caching

Caching is required, but caching should target routing data rather than validation results.

### What to Cache

The resolver should cache:

- the current plugin catalog for the configured vendor
- routing indexes derived from plugin metadata
- fast lookups such as issuer-to-plugin or prefix-to-plugin mappings

### What Not to Cache Here

This design does not require the resolver to cache authentication decisions or token validity. Those concerns belong to
plugin implementations when needed.

### Cache Behavior

The cache should make the common path cheap:

- repeated JWTs from the same issuer should not require repeated full plugin catalog scans
- repeated opaque token families should route without repeated registry lookups

The cache is an optimization over the metadata model, not a source of truth. The source of truth remains the registered
plugin instances in the types registry.

At a high level, the resolver cache should include:

- the current plugin catalog for the configured `vendor`
- indexes such as `issuer -> plugin candidates`
- indexes such as `opaque prefix -> plugin candidates`
- a lightweight mapping from explicit client-credentials route key to plugin candidates

It should not cache a single globally selected plugin instance as the current `GtsPluginSelector` flow does today.

### Cache Invalidation

The resolver should use a combination of TTL-based refresh and refresh-on-miss:

- the plugin catalog is refreshed from the types registry periodically (e.g. every 60 seconds)
- if a routing lookup produces no match and the catalog has not been refreshed recently, the resolver performs a
  one-shot catalog refresh and retries routing once before returning an error
- after a catalog refresh, the routing indexes are rebuilt and catalog-level validation is re-evaluated

This approach avoids the need for event-driven notifications from the types registry while ensuring that newly
registered plugins become visible within a bounded time window. The refresh-on-miss path acts as a safety net for
plugins registered between periodic refreshes.

## Provider-Specific Logic

All provider-specific behavior is encapsulated inside plugins. The resolver is provider-agnostic by design.

Examples of provider-specific concerns that belong exclusively to plugins:

- JWKS endpoint discovery and key rotation (OIDC plugins)
- remote token introspection via provider API (OAuth2-only plugins like GitHub)
- claim mapping rules (which JWT claims map to which `SecurityContext` fields)
- token refresh or caching strategies
- identity binding to internal platform subjects

The resolver's only provider-adjacent responsibility is the token classification heuristic (JWT vs opaque), which is a
generic syntactic check and does not encode knowledge about any specific provider.

This means adding support for a new authentication provider (e.g. Azure AD, Okta, GitLab) requires only a new plugin
registration with appropriate routing metadata, as long as the provider's tokens fit into existing route kinds
(`jwt_issuer`, `opaque_prefix`, etc.). If a new provider requires a fundamentally different routing mechanism, a new
route kind would need to be added to the resolver.

## Appendix: GitHub Token to `SecurityContext` (Illustrative Example)

This section illustrates how a specific plugin (GitHub) would convert an external identity into the platform
`SecurityContext`. It is not part of the routing contract; it is included to show the end-to-end flow from token
arrival to identity resolution.

The GitHub plugin is responsible for converting a GitHub-authenticated identity into the platform `SecurityContext`
expected by downstream modules.

At a conceptual level, that conversion should look like this:

1. the resolver routes an incoming GitHub token to the GitHub plugin using opaque-token metadata
2. the GitHub plugin validates the token using GitHub-specific authentication rules
3. the plugin obtains the external GitHub subject information needed for identity resolution
4. the plugin maps the external identity to an internal platform subject
5. the plugin builds `SecurityContext` using internal platform identifiers

### Conceptual Mapping

- GitHub user identifier or login
    - input identity from GitHub
- internal subject identifier
    - becomes `SecurityContext.subject_id`
- internal home tenant derived from platform-side identity binding or membership source
    - becomes `SecurityContext.subject_tenant_id`
- normalized token scopes or platform capability ceiling derived from GitHub token scopes
    - becomes `SecurityContext.token_scopes`
- provider-specific subject classification if needed
    - becomes `SecurityContext.subject_type`
- original bearer token when downstream forwarding is required
    - becomes `SecurityContext.bearer_token`

The key architectural point is that `GitHub` itself does not define the platform `SecurityContext`. The plugin does. It
uses GitHub as the authentication source and produces a normalized platform identity for the rest of the system.

This also means that GitHub authentication is expected to depend on a platform-side identity binding model. How that
binding is stored or provisioned is outside the scope of this design note, but the plugin must not expose raw external
identity data as a substitute for platform subject identity.

## Failure Semantics

The resolver should fail closed in these cases:

- no plugin matches the request
- more than one plugin matches and ambiguity cannot be resolved deterministically
- the selected plugin is not currently available in `ClientHub`

This keeps plugin selection predictable and avoids accidental authentication by the wrong plugin.

### Error Mapping

Routing failures should map to existing `AuthNResolverError` variants without introducing new ones:

- no plugin matches the incoming token -> `Unauthorized` (the caller should not learn internal routing details)
- ambiguous match (configuration error) -> `Internal` (with structured logging for operators)
- plugin not available in `ClientHub` -> `ServiceUnavailable` (existing variant)
- no plugins registered at all for the vendor -> `NoPluginAvailable` (existing variant)

The distinction between "no plugins registered" and "no plugin matched this specific token" is visible in logs but not
in the error returned to the caller. From the caller's perspective, an unmatched token is simply unauthorized.

## Summary

The core change is to evolve `AuthNResolverPluginSpecV1` from an empty marker spec into a routing metadata contract.

With that change:

- plugin selection becomes per-request instead of process-global
- multiple AuthN plugins can coexist under the same vendor
- the resolver remains lightweight and declarative
- token classification uses a cheap, generic heuristic (JWT vs opaque) with no provider-specific logic
- routing uses deterministic rules: exact match > longest-prefix > fail-closed on ambiguity
- `exchange_client_credentials()` routes via an explicit `provider` hint from the caller
- caching targets routing indexes with TTL-based refresh and refresh-on-miss
- catalog-level validation detects configuration conflicts eagerly
- all provider-specific logic (validation, introspection, identity mapping) stays inside plugins
- adding a new provider requires only a new plugin, provided its tokens fit existing route kinds
