# PRD — Mini Chat

## 1. Overview

### 1.1 Purpose

Mini Chat is a multi-tenant AI chat module that provides users with a conversational interface backed by a large language model. Users can send messages, receive streamed responses in real time, upload documents, and ask questions about uploaded content. The module enforces strict tenant isolation, usage-based cost controls, and audit logging.

### 1.2 Background / Problem Statement

The platform requires an integrated AI assistant that gives users the ability to have multi-turn conversations with an LLM and ground those conversations in their own documents. Without this capability, users must rely on external tools (ChatGPT, etc.), which creates data governance risks, lacks integration with platform access controls, and provides no cost visibility to tenant administrators.

Current gaps: no native chat experience within the platform; no way to query uploaded documents via LLM; no per-user usage tracking or quota enforcement for AI features; no audit trail for AI interactions.

### 1.3 Goals (Business Outcomes)

- Provide a stable, production-ready AI chat with real-time streaming and persistent conversation history
- Enable document-aware conversations: users upload files and ask questions grounded in document content
- Guarantee tenant data isolation and enforce access control via `ai_chat` license feature
- Control operational costs through per-user quotas, token budgets, and tool-call limits
- Maintain an audit trail of all AI interactions (prompts, responses, policy decisions) for compliance

### 1.4 Glossary

| Term | Definition |
|------|------------|
| Chat | A persistent conversation between a user and the AI assistant |
| Message | A single turn within a chat (user input or assistant response) |
| Attachment | A document file uploaded to a chat for question answering |
| Thread Summary | A compressed representation of older messages, used to keep long conversations within token limits |
| Vector Store | An OpenAI-hosted index of document embeddings, scoped per tenant, used for document search |
| File Search | An LLM tool call that retrieves relevant excerpts from uploaded documents |
| Token Budget | The maximum number of input/output tokens allowed per request |
| Temporary Chat | A chat marked for automatic deletion after 24 hours |
| OAGW | Outbound API Gateway — platform service that handles external API calls and credential injection |

## 2. Actors

### 2.1 Human Actors

#### Chat User

**ID**: `cpt-cf-mini-chat-actor-chat-user`

**Role**: End user who creates chats, sends messages, uploads documents, and receives AI responses. Belongs to a tenant and is subject to that tenant's license and quota policies.
**Needs**: Real-time conversational AI; ability to ask questions about uploaded documents; persistent chat history; clear feedback when quotas are exceeded.

### 2.2 System Actors

#### OpenAI

**ID**: `cpt-cf-mini-chat-actor-openai`

**Role**: External LLM provider. Processes chat completion requests, hosts uploaded files, maintains vector stores for document search. All communication routed through OAGW.

#### Cleanup Scheduler

**ID**: `cpt-cf-mini-chat-actor-cleanup-scheduler`

**Role**: Scheduled process that deletes expired temporary chats and purges associated external resources (files, vector store entries) after the retention period.

## 3. Operational Concept & Environment

No module-specific environment constraints beyond platform defaults.

## 4. Scope

### 4.1 In Scope

- Chat CRUD (create, list, get, delete)
- Real-time streamed AI responses (SSE)
- Persistent conversation history
- Document upload and document-aware question answering via file search
- Thread summary compression for long conversations
- Temporary chats with 24h auto-deletion
- Per-user usage quotas (daily, monthly) with auto-downgrade to base model
- File search call limits per message and per user/day
- Token budget enforcement and context truncation
- License feature gate (`ai_chat`)
- Append-only audit logging of all interactions
- Streaming cancellation when client disconnects
- Cleanup of external resources (OpenAI files, vector store entries) on chat deletion

### 4.2 Out of Scope

- Projects or shared/collaborative chats
- Full-text search across chat history
- Multi-provider LLM support (only OpenAI for P0)
- Complex retrieval policies beyond simple limits
- Per-workspace vector stores (only per-tenant for P0)
- Image or non-document file support
- Custom audit storage (audit events are emitted to platform `audit_service`)
- Chat export or migration

## 5. Functional Requirements

### 5.1 Core Chat

#### Chat CRUD

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-chat-crud`

The system MUST allow authenticated users to create, list, retrieve, and delete chats. Each chat belongs to exactly one user within one tenant. Listing returns chats for the current user ordered by most recent activity. Retrieval returns chat metadata and the most recent messages. Deletion soft-deletes the chat and triggers cleanup of associated external resources.

**Rationale**: Users need to manage their conversations — create new ones, resume existing ones, and remove ones they no longer need.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Streamed Chat Responses

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-chat-streaming`

The system MUST deliver AI responses as a real-time token stream (SSE). The user sends a message and immediately begins receiving response tokens as they are generated. The stream terminates with a completion event containing the message ID and token usage.

**Rationale**: Streaming provides perceived low latency and matches user expectations from consumer AI chat products.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Conversation History

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-conversation-history`

The system MUST persist all user and assistant messages. On each new user message, the system MUST include relevant conversation history in the LLM context to maintain conversational coherence.

**Rationale**: Multi-turn conversations require the AI to remember prior context within the same chat.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Streaming Cancellation

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-streaming-cancellation`

The system MUST detect client disconnection during a streaming response and cancel the in-flight LLM request. Cancellation MUST propagate through the entire request chain to terminate the external API call.

**Rationale**: Prevents wasted compute and cost when the user navigates away or closes the browser.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

### 5.2 Document Support

#### File Upload

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-file-upload`

The system MUST allow users to upload document files (not images) to a chat. Uploaded files are processed and indexed for search. The system MUST return an attachment identifier and processing status.

**Rationale**: Users need to ground AI conversations in their own documents (contracts, policies, reports).
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Document Question Answering (File Search)

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-file-search`

The system MUST support answering questions about uploaded documents by retrieving relevant excerpts during chat. File search MUST be scoped to the user's tenant. The system MUST limit file search to at most 2 retrieval calls per message.

**Rationale**: The primary value of document upload is the ability to ask questions and get answers grounded in document content.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Document Summary on Upload

- [ ] `p2` - **ID**: `cpt-cf-mini-chat-fr-doc-summary`

The system MUST generate a brief summary of each uploaded document at upload time. The summary is stored and used in the conversation context to give the AI general awareness of attached documents without requiring a search call.

**Rationale**: Improves AI response quality when the user asks general questions about attached documents.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

### 5.3 Conversation Management

#### Thread Summary Compression

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-thread-summary`

The system MUST compress older conversation history into a summary when the conversation exceeds defined thresholds (message count, token count, or turn count). The summary MUST preserve key facts, decisions, names, and document references. Summarized messages are retained in storage but replaced by the summary in the LLM context.

**Rationale**: Long conversations would exceed LLM context limits and increase costs without compression.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Temporary Chats

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-temporary-chat`

The system MUST allow users to mark a chat as temporary. Temporary chats MUST be automatically deleted (including all associated external resources) after 24 hours.

**Rationale**: Users need disposable conversations for quick questions without cluttering their chat list.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`, `cpt-cf-mini-chat-actor-cleanup-scheduler`

### 5.4 Cost Control & Governance

#### Per-User Usage Quotas

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-quota-enforcement`

The system MUST enforce per-user usage limits on a daily and monthly basis. Tracked metrics: input tokens, output tokens, file search calls, premium model calls. When a user exceeds their premium model quota, the system MUST auto-downgrade to a base model. When all quotas are exhausted, the system MUST reject requests with a clear error.

**Rationale**: Prevents runaway costs from individual users and ensures fair resource distribution across a tenant.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Token Budget Enforcement

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-token-budget`

The system MUST enforce a maximum input token budget per request. When the assembled context exceeds the budget, the system MUST truncate lower-priority content (old messages, document summaries, retrieval excerpts) while preserving the system prompt and thread summary. A reserve for output tokens MUST always be maintained.

**Rationale**: Prevents requests from exceeding provider context limits and controls per-request cost.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### License Gate

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-license-gate`

The system MUST verify that the user's tenant has the `ai_chat` feature enabled via the platform's `license_manager`. Requests from tenants without this feature MUST be rejected with HTTP 403.

**Rationale**: AI chat is a premium feature gated by the tenant's license agreement. License verification is delegated to the platform `license_manager`.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Audit Logging

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-audit`

The system MUST emit a structured audit event to the platform's `audit_service` for every AI interaction. Each event MUST include: tenant, user, chat reference, event type, model used, token counts, latency metrics, and policy decisions (quota checks, license gate results). Mini Chat does not store audit data locally.

**Rationale**: Compliance and cost analysis require a complete record of all AI usage. Audit storage and immutability are the platform `audit_service` responsibility.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

#### Cost Metrics

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-cost-metrics`

The system MUST log the following metrics for every LLM request: model, input tokens, output tokens, file search call count, time to first token, total latency, tenant ID, and user ID. The system MUST compute an estimated cost for each request.

**Rationale**: Enables cost monitoring, budget alerts, and billing attribution per tenant/user.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`

### 5.5 Data Lifecycle

#### Chat Deletion with Resource Cleanup

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-fr-chat-deletion-cleanup`

When a chat is deleted, the system MUST remove all associated files from the external provider and remove file entries from the tenant's vector store. Local data MUST be soft-deleted or anonymized per the retention policy.

**Rationale**: Prevents orphaned external resources and ensures data governance compliance on deletion.
**Actors**: `cpt-cf-mini-chat-actor-chat-user`, `cpt-cf-mini-chat-actor-cleanup-scheduler`

## 6. Non-Functional Requirements

### 6.1 Module-Specific NFRs

#### Tenant Isolation

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-nfr-tenant-isolation`

Tenant data MUST never be accessible to users from another tenant. All data queries, file operations, and vector store searches MUST be scoped by tenant. The API MUST NOT accept raw external resource identifiers (file IDs, vector store IDs) from clients.

**Threshold**: Zero cross-tenant data leaks
**Rationale**: Multi-tenant SaaS with sensitive documents requires strict data boundaries.
**Architecture Allocation**: See DESIGN.md section 2.1 (Tenant-Scoped Everything principle)

#### Cost Predictability

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-nfr-cost-control`

Per-user LLM costs MUST be bounded by configurable daily and monthly quotas. File search costs MUST be bounded by per-message and per-day call limits. The system MUST track and report actual costs per tenant and user.

**Threshold**: No user exceeds configured quota; estimated cost available for 100% of requests
**Rationale**: Unbounded LLM usage can generate unexpected costs; tenants need cost predictability.
**Architecture Allocation**: See DESIGN.md section 3.2 (quota_service component)

#### Streaming Latency

- [ ] `p2` - **ID**: `cpt-cf-mini-chat-nfr-streaming-latency`

The system MUST NOT add more than 100ms overhead to time-to-first-token beyond the LLM provider's own latency. Streaming tokens MUST be relayed without buffering.

**Threshold**: Platform overhead < 100ms P95 (excluding provider latency)
**Rationale**: Users expect near-instant response start in a chat interface.
**Architecture Allocation**: See DESIGN.md section 2.1 (Streaming-First principle)

#### Data Retention Compliance

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-nfr-data-retention`

Temporary chats MUST be deleted within 25 hours of creation. Deleted chat resources (files, vector store entries) at the external provider MUST be removed within 1 hour of chat deletion.

**Threshold**: 100% of temporary chats cleaned up within SLA; 100% of external resources removed
**Rationale**: Regulatory and customer contractual requirements for data lifecycle management.
**Architecture Allocation**: See DESIGN.md section 4 (Cleanup on Chat Deletion)

## 7. Public Library Interfaces

### 7.1 Public API Surface

#### Chat REST API

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-interface-rest-api`

**Type**: REST API
**Stability**: stable
**Description**: Public HTTP API for chat management, message streaming, and file upload. All endpoints require authentication and tenant license verification.
**Breaking Change Policy**: Versioned via URL prefix (`/v1/`). Breaking changes require new version.

### 7.2 External Integration Contracts

#### SSE Streaming Contract

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-contract-sse-streaming`

**Direction**: provided by library
**Protocol/Format**: Server-Sent Events (SSE) over HTTP
**Compatibility**: Event types (`token`, `done`, `error`) and their payload schemas are stable within a major API version.

## 8. Use Cases

#### UC-001: Send Message and Receive Streamed Response

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-usecase-send-message`

**Actor**: `cpt-cf-mini-chat-actor-chat-user`

**Preconditions**:
- User is authenticated and tenant has `ai_chat` license
- Chat exists and belongs to the user

**Main Flow**:
1. User sends a message to an existing chat
2. System checks user quota
3. System assembles conversation context (summary, recent messages, document summaries)
4. System streams AI response tokens back to the user in real time
5. System persists both user message and assistant response
6. System logs audit event with usage metrics

**Postconditions**:
- Message and response persisted in chat history
- Usage counters updated
- Audit event recorded

**Alternative Flows**:
- **Quota exceeded**: System rejects request with `quota_exceeded` error; no LLM call made
- **Client disconnects**: System cancels in-flight LLM request; partial response may be persisted

#### UC-002: Send Message with Document Search

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-usecase-doc-search`

**Actor**: `cpt-cf-mini-chat-actor-chat-user`

**Preconditions**:
- Same as UC-001
- At least one document is attached to the chat and has `ready` status

**Main Flow**:
1. User sends a message that references document content
2. System detects that file search is needed
3. System retrieves relevant excerpts from the tenant's document index
4. System includes excerpts in the LLM context alongside conversation history
5. System streams AI response grounded in document content

**Postconditions**:
- Response incorporates information from uploaded documents
- File search call counted against user quota

**Alternative Flows**:
- **File search limit reached**: System proceeds without retrieval; response based on conversation context and document summaries only

#### UC-003: Upload Document

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-usecase-upload-document`

**Actor**: `cpt-cf-mini-chat-actor-chat-user`

**Preconditions**:
- User is authenticated and tenant has `ai_chat` license
- Chat exists and belongs to the user
- File is a supported document type and within size limits

**Main Flow**:
1. User uploads a document file to a chat
2. System stores the file with the external provider
3. System indexes the file in the tenant's document search index
4. System generates a brief summary of the document
5. System returns attachment ID and `ready` status

**Postconditions**:
- Document is searchable in subsequent chat messages
- Document summary available for context assembly

**Alternative Flows**:
- **Unsupported file type**: System rejects with `unsupported_file_type` error
- **File too large**: System rejects with `file_too_large` error
- **Processing failure**: Attachment status set to `failed`; user informed

#### UC-004: Delete Chat

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-usecase-delete-chat`

**Actor**: `cpt-cf-mini-chat-actor-chat-user`

**Preconditions**:
- Chat exists and belongs to the user

**Main Flow**:
1. User requests chat deletion
2. System soft-deletes the chat
3. System removes all associated files from external provider
4. System removes file entries from tenant document search index
5. System records audit event

**Postconditions**:
- Chat no longer appears in user's chat list
- External resources cleaned up
- Audit trail preserved

#### UC-005: Temporary Chat Auto-Deletion

- [ ] `p1` - **ID**: `cpt-cf-mini-chat-usecase-temporary-chat-cleanup`

**Actor**: `cpt-cf-mini-chat-actor-cleanup-scheduler`

**Preconditions**:
- Temporary chat exists with creation time > 24 hours ago

**Main Flow**:
1. Scheduler identifies expired temporary chats
2. System executes the same deletion flow as UC-004 for each expired chat

**Postconditions**:
- All expired temporary chats and their external resources are removed

## 9. Acceptance Criteria

- [ ] User can create a chat, send messages, and receive streamed AI responses with < 100ms platform overhead
- [ ] User can upload a document and ask questions that are answered using document content
- [ ] Users from different tenants cannot access each other's chats, documents, or search results
- [ ] User exceeding daily quota receives a clear error message and is auto-downgraded to a base model
- [ ] Temporary chats are automatically deleted within 25 hours
- [ ] Deleted chat resources are removed from the external provider within 1 hour
- [ ] Every AI interaction produces an immutable audit event with usage metrics
- [ ] Long conversations (50+ turns) remain functional via thread summary compression

## 10. Dependencies

| Dependency | Description | Criticality |
|------------|-------------|-------------|
| Platform API Gateway | HTTP routing, SSE transport | `p1` |
| Platform AuthN | User authentication, tenant resolution | `p1` |
| Outbound API Gateway (OAGW) | External API egress, credential injection | `p1` |
| OpenAI Responses API | LLM chat completion (streaming and non-streaming) | `p1` |
| OpenAI Files API | Document upload and storage | `p1` |
| OpenAI Vector Stores / File Search | Document indexing and retrieval | `p1` |
| PostgreSQL | Primary data storage | `p1` |
| Platform license_manager | Tenant feature flag resolution (`ai_chat`) | `p1` |
| Platform audit_service | Audit event ingestion (prompts, responses, usage, policy decisions) | `p1` |

## 11. Assumptions

- OpenAI Responses API, Files API, and File Search remain stable and available
- OAGW supports streaming SSE relay and credential injection for OpenAI endpoints
- Platform AuthN provides `user_id` and `tenant_id` in the security context for every request
- Platform `license_manager` can resolve the `ai_chat` feature flag synchronously
- Platform `audit_service` is available to receive audit events
- One OpenAI vector store per tenant is sufficient for P0 document volumes
- Thread summary quality is adequate for maintaining conversational coherence over long chats

## 12. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| OpenAI API changes or deprecation | Feature breakage; requires rework | Pin API versions; monitor deprecation notices; design for eventual multi-provider |
| OpenAI outage or degraded performance | Chat unavailable or slow | Circuit breaking via OAGW; clear error messaging to users; eventual fallback provider (P2+) |
| Cost overruns from unexpected usage patterns | Budget exceeded at tenant level | Per-user quotas; file search call limits; token budgets; cost monitoring and alerts |
| Thread summary loses critical context | Degraded conversation quality over long chats | Include explicit instructions to preserve decisions, facts, names, document refs; allow users to start new chats |
| Vector store data consistency on deletion | Orphaned files at OpenAI | Idempotent cleanup with retry; reconciliation job for detecting orphans |
| Large document volumes per tenant exceeding vector store limits | Search quality degrades; upload failures | Monitor per-tenant file counts; enforce upload limits; plan per-workspace stores (P2) |

## 13. Open Questions

- What are the specific daily and monthly quota values per user? (configurable per tenant, or platform-wide defaults?)
- What document file types and size limits are supported in P0? (PDF, DOCX, TXT? Max 50MB?)
- What LLM model is used for P0 — always `gpt-4o`, or configurable per tenant?
- What is the base model for auto-downgrade when premium quota is exhausted? (`gpt-4o-mini`?)
- What are the thread summary trigger thresholds? (20 messages, 15 user turns, or token-based?)
- Is the system prompt configurable per tenant, or fixed platform-wide?

## 14. Traceability

- **Design**: [DESIGN.md](./DESIGN.md)
- **ADRs**: [ADR/](./ADR/) (planned)
- **Features**: [features/](./features/) (planned)
