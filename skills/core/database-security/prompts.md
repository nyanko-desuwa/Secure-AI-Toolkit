# Database Security Prompt Examples

Prompts that produce findings rather than generic advice. Each names a scope, an exploitation
path, and an output shape.

## Review query construction

```text
Review src/repositories and src/routes for database injection. Trace request data into psycopg,
SQLAlchemy, Prisma, and Knex sinks. Include raw/extra/text/$queryRawUnsafe/whereRaw escape hatches.
For every finding give file:line, input source, sink, A05:2025 + ASVS V1 + CWE, a concrete
payload shape, and a parameterized or allowlisted fix. Do not flag server-constant SQL.
```

Why it works: it names the sinks and asks for dataflow. Searching only for `SELECT` misses ORM
raw fragments and second-order injection.

## Check the parameterization gaps

```text
Find every dynamic identifier, ORDER BY direction, LIKE pattern, IN list, and dynamic WHERE in
this diff. For each, say whether the value is a bind, identifier allowlist, or server-owned
fragment. Flag an empty or unbounded IN list and wildcard searches that can force a scan.
```

Why it works: "are queries parameterized?" invites a yes even when identifiers are interpolated.

## Review ORM escape hatches and mass assignment

```text
Audit the Prisma and Knex code for $queryRawUnsafe, $executeRawUnsafe, raw, whereRaw, orderByRaw,
and request bodies passed to create/update. Show safe uses too. For each unsafe use map to
A05/CWE-89 or A01/CWE-915 and give the smallest fix.
```

Why it works: asking for safe uses prevents keyword matching from becoming a false-positive list.

## Hunt second-order injection

```text
Trace values stored in report definitions, imports, saved filters, and admin-configured fields.
Find any stored value later used as SQL text, a column name, an expression, or a raw ORM fragment.
Treat the database row as untrusted at the later sink. Give a write-time and read-time fix.
```

## Review Mongo-style filters

```text
Find every MongoDB/Mongoose query object built from req.body, req.query, object spread, or JSON
parse. Check nested objects and $where/$expr. For each finding show the operator-injection payload
shape and replace sanitization with a strict typed schema. Map to A05:2025, ASVS V2, CWE-943.
```

## Review tenant isolation

```text
For tenant A and tenant B, trace every invoice read, write, delete, export, and background job.
Identify where tenant context is derived and enforced. Flag any query the caller must remember to
scope. Check PostgreSQL ENABLE/FORCE RLS, USING/WITH CHECK, app role bypass, and transaction-local
context in the connection pool. Map to A01:2025, ASVS V8, CWE-566.
```

## Review grants and database credentials

```text
Read migrations, infrastructure config, and connection setup. Build a matrix of owner, migration,
runtime, reporting, and backup roles with effective grants. Flag runtime DDL, GRANT ALL,
superuser, PostgreSQL ownership, MySQL FILE/SUPER, missing default privileges, and one credential
shared by multiple services. Map findings to A02:2025, ASVS V13, CWE-250.
```

## Review encryption and connection security

```text
For each sensitive column, state what TDE, column encryption, or application encryption protects
against and does not. Check AEAD nonce handling, key custody, deterministic equality leakage, and
HMAC lookup indexes. Then verify database TLS does certificate and hostname checks and connection
strings never reach source or logs. Cite A04, ASVS V11/V12/V14, and the applicable CWE.
```

## Review backups, audit, and migrations

```text
Review this migration and its operational plan as a security change. Check destructive DDL,
unbounded data updates, grants/default privileges, runtime-vs-migration credentials, encrypted
backups, restore access, restore tests, and audit records for backup/restore and sensitive reads.
State what cannot be verified from code.
```

## Write regression tests

```text
Add database security tests for: quote/comment SQL payloads; identifier rejection; literal % and _
in LIKE; empty and oversized IN lists; Mongo {$ne:null} objects rejected as wrong types; known
cross-tenant primary key returns no rows; RLS context does not leak through a size-one pool; and
the runtime role cannot CREATE TABLE. Report which tests need a real database.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is the database secure?" | No scope or threat; produces a checklist recital |
| "Parameterize all queries" | Misses identifiers, sort, list arity, query objects, and second-order sinks |
| "Ban raw SQL" | Not enforceable and hides necessary raw uses instead of reviewing them |
| "Add tenant_id to every query" | Leaves the boundary as a rule each caller must remember |
| "Encrypt the database" | Does not say whether the threat is stolen disks, DBAs, injection, or backups |
| "Make Mongo safe from SQL injection" | Wrong interpreter and wrong fix; operator injection needs type checks |
| "Turn on full audit" | Ignores cost, retention, alerting, and who can delete the log |
| "Make the migration reversible" | A down migration cannot resurrect dropped or overwritten data |
