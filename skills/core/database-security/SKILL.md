---
name: database-security
description: 'Secure the data layer when writing queries, ORM code, migrations, or database configuration. Covers injection, tenant isolation, least privilege, encryption, and audit. Triggers: "SQL injection", "NoSQL injection", "ORM", "parameterized query", "row-level security", "multi-tenant", "migration", "truy vấn", "cơ sở dữ liệu".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Database Security

The data layer is where a small mistake reads the whole table. This skill covers the query,
the credential that runs it, the tenant boundary it crosses, and the backup it ends up in.

## When to Use

- Writing or reviewing SQL, an ORM query, or a query builder call
- Building a dynamic query: sort order, filters, `IN` lists, search
- Adding a migration, or reviewing one
- Designing multi-tenant data access
- Choosing where to encrypt: disk, column, or application
- Setting up database roles, grants, connection strings, or TLS
- Investigating what an attacker could reach with a leaked database credential

## The Four Questions

Ask these before writing data-layer code. Most findings fall out of one of them.

1. Does any part of this query come from a request? If yes, is it a value (parameterize) or
   an identifier (allowlist)?
2. What can this credential do that the feature does not need?
3. If the query is correct but the caller forgets the tenant filter, what happens?
4. If someone walks off with a backup, what do they have in cleartext?

## Workflow

### 1. Trace the input to the sink

Follow request data to the query, and keep following. Second-order injection happens when
input is stored safely and interpolated later by a different function. Grep for the sink, not
the source: `execute(`, `raw(`, `$queryRawUnsafe`, `whereRaw`, `createQuery(`, f-strings and
template literals containing `SELECT`, `WHERE`, or `ORDER BY`.

### 2. Classify each interpolation

| What is dynamic | Control |
|---|---|
| A value | Bind parameter. Never formatting |
| A column or table name | Allowlist map from input key to a fixed identifier |
| Sort direction | Allowlist. `{"asc": "ASC", "desc": "DESC"}` |
| A list for `IN` | Generated placeholders, or an array parameter. Cap the length |
| A `LIKE` pattern | Bind the parameter and escape `%`, `_`, `\` with an `ESCAPE` clause |
| A whole predicate | Compose from server-defined fragments, each with its own binds |

Parameterization is not a universal answer. It covers values only. Everything else on that
list needs an allowlist, and that is where injection survives in careful codebases.

### 3. Check the query object shape, not just the string

`A05:2025` covers NoSQL too. A MongoDB-style query is a document, so injection is structural:
`{"password": {"$ne": null}}` needs no quotes to break. The fix is type checking, not
escaping. See [best-practices.md](best-practices.md#nosql-operator-injection).

### 4. Push the boundary below the application

An access rule the application must remember is a rule the next handler will forget. Move
tenant and ownership scoping into the data layer: a repository that cannot build an unscoped
query, or row-level security so the engine refuses. See
[best-practices.md](best-practices.md#multi-tenancy).

### 5. Check the credential

Runtime credentials do not need DDL. Read paths do not need `UPDATE`. Two roles - one for
migrations, one for runtime - turn a SQL injection from schema destruction into a data read.
See [references/privilege-model.md](references/privilege-model.md).

### 6. Verify

Run [checklist.md](checklist.md). Skip sections that do not apply, with a reason.

## Severity

Rank by what the flaw reaches, not by its name.

- **Critical** - injection reaching an interpreter with a broad credential, cross-tenant read
  or write, cleartext secrets in a backup or replica
- **High** - injection behind auth, tenant filter missing on one handler, app credential with
  DDL or superuser, unverified TLS to the database over a shared network
- **Medium** - deterministic encryption leaking equality on a low-cardinality column, N+1 on
  an unauthenticated endpoint, audit gap on sensitive reads
- **Low** - defence in depth missing where another layer still holds

An `ORDER BY` interpolation on an admin-only endpoint is not critical. Say why.

## Related Skills

- `owasp` - the standards this skill maps to
- `secrets-management` - where the connection string lives and how it rotates
- `logging-audit` - what audit records go to, and who watches them
- `api-security` - the layer above, where the tenant is established
- `redis-security` - Redis/Valkey ACLs, transport, persistence, and command/key authorization

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the guidance cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/injection-standards.md](references/injection-standards.md) - A05, ASVS V1, CWEs
- [references/privilege-model.md](references/privilege-model.md) - roles, grants, RLS
- [examples/README.md](examples/README.md) - eight vulnerable/fixed pairs
