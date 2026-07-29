# Database Privilege Model

Role splits, grants, and RLS. The credential is the backstop for the injection you did not catch:
the same payload as an owner drops tables; as a narrow role it reads only granted rows.

Maps to `A02:2025`, `A01:2025`, `CWE-250`, ASVS V8 and V13. Syntax checked 2026-07-28
against PostgreSQL 17 and MySQL 8.4 documentation.

## Roles

| Role | Can | Cannot | Used by |
|---|---|---|---|
| `app_owner` | Own objects, DDL | Log in | Nobody directly |
| `app_migrate` | DDL via `SET ROLE` | Run outside migration job | Migration job |
| `app_runtime` | Named DML grants | DDL, role changes | Web and workers |
| `app_readonly` | Named `SELECT` grants | Any write | Reporting, replicas |

Owner and migrator are separate because ownership carries DDL rights no `REVOKE` removes. Park
ownership on a NOLOGIN role; let the migration job assume it briefly.

## PostgreSQL

```sql
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE app_migrate LOGIN PASSWORD :'migrate_password' IN ROLE app_owner;
CREATE ROLE app_runtime LOGIN PASSWORD :'runtime_password';
CREATE ROLE app_readonly LOGIN PASSWORD :'readonly_password';

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA app AUTHORIZATION app_owner;
GRANT USAGE ON SCHEMA app TO app_runtime, app_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_readonly;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app
  GRANT SELECT ON TABLES TO app_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app
  GRANT USAGE ON SEQUENCES TO app_runtime;

-- Append-only audit data cannot be rewritten by the app.
REVOKE UPDATE, DELETE ON app.audit_log FROM app_runtime;
GRANT SELECT, INSERT ON app.audit_log TO app_runtime;
```

The migration job connects as `app_migrate`, uses `SET ROLE app_owner`, runs DDL, then
`RESET ROLE`. Runtime DDL succeeding is a finding, not a convenience.

## MySQL 8.4

MySQL has no per-object owner; split by grants.

```sql
CREATE ROLE app_runtime_role, app_readonly_role, app_migrate_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO app_runtime_role;
GRANT SELECT ON appdb.* TO app_readonly_role;
GRANT ALL PRIVILEGES ON appdb.* TO app_migrate_role;

CREATE USER 'app_runtime'@'10.0.%' IDENTIFIED BY 'placeholder' REQUIRE SSL;
GRANT app_runtime_role TO 'app_runtime'@'10.0.%';
SET DEFAULT ROLE app_runtime_role TO 'app_runtime'@'10.0.%';
```

Never grant `FILE`, `SUPER`, `PROCESS`, or `SHUTDOWN` to the app. `FILE` turns injection into
arbitrary file read with `LOAD_FILE()`.

## PostgreSQL row-level security

```sql
ALTER TABLE app.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app.invoices
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

`USING` filters visible rows; `WITH CHECK` constrains new row state. `FORCE` covers the owner,
which otherwise bypasses policies. An unset setting yields NULL and denies; do not use a
`COALESCE` fallback to the row's tenant.

Set context per transaction, never per pooled session:

```python
with conn.transaction():
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),))
    rows = conn.execute("SELECT id, total_cents FROM app.invoices").fetchall()
```

The third argument makes the value transaction-local. Session scope can carry tenant A into
tenant B's request when the pool reuses a connection.

MySQL has no RLS. Use scoped views with grants or a repository that cannot emit unscoped SQL,
and state that this is weaker than engine enforcement.

## Connection checks

| Check | Failure it prevents | Cite |
|---|---|---|
| PostgreSQL `sslmode=verify-full` | `require` encrypts but does not verify certificate/host | A04, CWE-319, ASVS V12 |
| MySQL `VERIFY_IDENTITY` | `REQUIRED` skips identity checks | A04, CWE-319, ASVS V12 |
| Secret-manager connection URI | Source, images, logs exposing credentials | A04, CWE-522, ASVS V13 |
| Private bind and one credential per service | Public scanning; shared blast radius | A02/A01, ASVS V13 |
| Short-lived credentials | Leaked secret remaining valid until a deploy | A04, CWE-522, ASVS V13 |

Fail on TLS downgrade. Rotate with an overlap: issue new, drain old pool connections, revoke old.

## Sources

- PostgreSQL 17 `GRANT` - <https://www.postgresql.org/docs/17/sql-grant.html>
- PostgreSQL 17 `CREATE POLICY` - <https://www.postgresql.org/docs/17/sql-createpolicy.html>
- PostgreSQL 17 SSL - <https://www.postgresql.org/docs/17/libpq-ssl.html>
- MySQL 8.4 roles - <https://dev.mysql.com/doc/refman/8.4/en/roles.html>
- MySQL 8.4 TLS - <https://dev.mysql.com/doc/refman/8.4/en/encrypted-connections.html>
- OWASP Database Security Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html>

All URLs checked 2026-07-28.
