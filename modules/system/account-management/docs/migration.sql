-- Created:  2026-04-19 by Virtuozzo
-- Updated:  2026-04-19 by Virtuozzo

-- Reference DDL for the Account Management source-of-truth schema.
-- This file is intentionally documentation-first: implementation migrations may
-- express the same logical schema through ModKit/SeaORM migration code.
-- Dialect: PostgreSQL reference DDL.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Tenants ──────────────────────────────────────────────────────────────────

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    status TEXT NOT NULL CHECK (status IN ('provisioning', 'active', 'suspended', 'deleted')),
    self_managed BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_type_uuid UUID NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT fk_tenants_parent
        FOREIGN KEY (parent_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    CONSTRAINT ck_tenants_root_depth
        CHECK ((parent_id IS NULL AND depth = 0) OR (parent_id IS NOT NULL AND depth > 0))
);

CREATE UNIQUE INDEX ux_tenants_single_root
    ON tenants ((1))
    WHERE parent_id IS NULL;

CREATE INDEX idx_tenants_parent_status
    ON tenants (parent_id, status);

CREATE INDEX idx_tenants_status
    ON tenants (status);

CREATE INDEX idx_tenants_type
    ON tenants (tenant_type_uuid);

CREATE INDEX idx_tenants_deleted_at
    ON tenants (deleted_at)
    WHERE deleted_at IS NOT NULL;

COMMENT ON TABLE tenants
    IS 'Canonical tenant hierarchy owned by Account Management. Tenant Resolver consumes this as the source-of-truth contract.';
COMMENT ON COLUMN tenants.self_managed
    IS 'Binary v1 barrier contract. true = self-managed tenant that downstream resolver/authz layers treat as a visibility barrier.';
COMMENT ON COLUMN tenants.tenant_type_uuid
    IS 'Deterministic UUIDv5 derived from the public chained tenant_type GTS identifier using the GTS namespace constant; compact storage/index key for tenant type assignment.';
COMMENT ON COLUMN tenants.depth
    IS 'Denormalized hierarchy depth used for advisory threshold checks and leaf-first retention cleanup ordering.';

-- ── Tenant metadata ──────────────────────────────────────────────────────────

CREATE TABLE tenant_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    schema_uuid UUID NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tenant_metadata_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT uq_tenant_metadata_tenant_schema_uuid
        UNIQUE (tenant_id, schema_uuid)
);

CREATE INDEX idx_tenant_metadata_schema_uuid
    ON tenant_metadata (schema_uuid);

COMMENT ON TABLE tenant_metadata
    IS 'Extensible tenant-scoped metadata entries validated against GTS-registered schemas.';
COMMENT ON COLUMN tenant_metadata.schema_uuid
    IS 'Deterministic UUIDv5 derived from schema_id using the GTS namespace constant; primary storage and index key for metadata lookups.';
COMMENT ON COLUMN tenant_metadata.value
    IS 'Opaque JSON payload validated in AM against the registered schema identified by schema_id.';

-- ── Conversion requests ──────────────────────────────────────────────────────

CREATE TABLE conversion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    target_mode TEXT NOT NULL CHECK (target_mode IN ('managed', 'self_managed')),
    initiator_side TEXT NOT NULL CHECK (initiator_side IN ('child', 'parent')),
    requested_by UUID NOT NULL,
    approved_by UUID NULL,
    cancelled_by UUID NULL,
    rejected_by UUID NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'cancelled', 'rejected', 'expired')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT fk_conversion_requests_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT ck_conversion_actor_columns
        CHECK (
            (status = 'pending'   AND approved_by IS NULL AND cancelled_by IS NULL AND rejected_by IS NULL) OR
            (status = 'approved'  AND approved_by IS NOT NULL AND cancelled_by IS NULL AND rejected_by IS NULL) OR
            (status = 'cancelled' AND approved_by IS NULL AND cancelled_by IS NOT NULL AND rejected_by IS NULL) OR
            (status = 'rejected'  AND approved_by IS NULL AND cancelled_by IS NULL AND rejected_by IS NOT NULL) OR
            (status = 'expired'   AND approved_by IS NULL AND cancelled_by IS NULL AND rejected_by IS NULL)
        )
);

CREATE UNIQUE INDEX ux_conversion_pending_per_tenant
    ON conversion_requests (tenant_id)
    WHERE status = 'pending' AND deleted_at IS NULL;

CREATE INDEX idx_conversion_tenant_status
    ON conversion_requests (tenant_id, status)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_conversion_expires
    ON conversion_requests (expires_at)
    WHERE status = 'pending' AND deleted_at IS NULL;

CREATE INDEX idx_conversion_deleted_at
    ON conversion_requests (deleted_at)
    WHERE deleted_at IS NOT NULL;

COMMENT ON TABLE conversion_requests
    IS 'Durable dual-consent mode transition records. Approved requests atomically change tenant barrier state; resolved history is soft-deleted after the configured retention window.';
COMMENT ON COLUMN conversion_requests.requested_by
    IS 'Canonical platform subject UUID from SecurityContext. Raw provider user identifiers are not stored here.';
COMMENT ON COLUMN conversion_requests.deleted_at
    IS 'Soft-delete tombstone for resolved-history retention. Default API reads exclude tombstoned rows.';
