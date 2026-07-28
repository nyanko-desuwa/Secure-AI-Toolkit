-- Tenant isolation in a shared PostgreSQL schema.
-- Pairs with examples/README.md#shared-schema-multi-tenancy-with-no-enforcement-point
-- A01:2025 · CWE-653 · ASVS V8

-- ============================================================
-- Vulnerable: tenant_id is a column, and nothing enforces it.
-- ============================================================

CREATE TABLE orders_vulnerable (
    id          bigserial PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    customer    text NOT NULL,
    total_cents bigint NOT NULL
);

-- Every read depends on the author remembering the predicate.
-- This one is correct:
--   SELECT * FROM orders_vulnerable WHERE tenant_id = $1 AND id = $2;
-- This one is a cross-tenant read, and it looks fine in review:
--   SELECT * FROM orders_vulnerable WHERE id = $2;
-- The nightly export, the admin script, and the metrics job are where it goes missing.

-- ============================================================
-- Fixed: row-level security, forced, with a non-bypassing role.
-- ============================================================

CREATE TABLE orders (
    id          bigserial PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    customer    text NOT NULL,
    total_cents bigint NOT NULL
);

CREATE INDEX orders_tenant_id_idx ON orders (tenant_id);

-- The application connects as this role. No BYPASSRLS, no SUPERUSER.
-- Table owners are exempt from their own policies unless FORCE is set,
-- so the application role must not own the table either.
CREATE ROLE app_runtime LOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO app_runtime;
GRANT USAGE, SELECT ON SEQUENCE orders_id_seq TO app_runtime;

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

-- current_setting(..., true) returns NULL when the setting is absent.
-- NULL::uuid = tenant_id is NULL, which is not true, so the row is filtered.
-- Absent tenant context therefore yields zero rows, never all rows.
CREATE POLICY orders_tenant_read ON orders
    FOR SELECT
    TO app_runtime
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- WITH CHECK covers writes: a tenant cannot insert or move a row into another tenant.
CREATE POLICY orders_tenant_write ON orders
    FOR ALL
    TO app_runtime
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Per-request, immediately after checking out the connection and before any query.
-- set_config with is_local = true scopes it to the transaction, so a pooled
-- connection cannot carry one request's tenant into the next.
-- BEGIN;
--   SELECT set_config('app.tenant_id', $1, true);
--   SELECT * FROM orders WHERE id = $2;
-- COMMIT;

-- ============================================================
-- Guardrails. Without these the policy above is decoration.
-- ============================================================

-- 1. Assert in CI that the runtime role cannot bypass RLS.
--    Expect exactly one row with both columns false.
SELECT rolname, rolsuper, rolbypassrls
FROM pg_roles
WHERE rolname = 'app_runtime';

-- 2. Assert every tenant-scoped table actually has RLS forced.
--    Expect zero rows.
SELECT c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND EXISTS (
      SELECT 1 FROM pg_attribute a
      WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0
  )
  AND NOT (c.relrowsecurity AND c.relforcerowsecurity);

-- Known gaps, stated rather than implied away:
--   - A bug that sets the wrong tenant_id on the connection still leaks. RLS moves the
--     failure from "forget the predicate" to "set the wrong principal", which is one
--     place instead of every query, but it is not zero places.
--   - Analytics and migrations run as a different role by necessity. Those paths need
--     their own review; RLS on app_runtime says nothing about them.
--   - A shared schema still shares a query planner and a disk. It does not bound
--     noisy-neighbour resource exhaustion (A06, unrestricted resource consumption).
