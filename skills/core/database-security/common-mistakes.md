# Database Security Common Mistakes

The failure, why it happens, and the fix. Mappings use OWASP Top 10 2025, ASVS 5.0, and CWE.

## “The values are parameterized, so the query is safe”

`A05:2025` · ASVS V1 · `CWE-89`

```python
# Values are safe; the identifier is still attacker-controlled.
cur.execute("SELECT * FROM users WHERE id = %s ORDER BY " + sort, (user_id,))
```

Placeholders cannot represent an identifier. An attacker can inject a second expression or a
secret-bearing sort. Fix with an allowlist map for columns and direction, then interpolate only
the server-selected strings. A regex denylist is not an allowlist.

## “We escaped the string”

`A05:2025` · ASVS V1 · `CWE-89`

Escaping is driver-, encoding-, and SQL-mode-dependent. It also cannot solve `ORDER BY`,
`IN` arity, or an entire predicate. Bind values. Generate placeholders for lists. Select
identifiers from fixed maps. Escaping a value by hand is a compatibility assumption disguised
as a control.

## “The ORM handles injection”

`A05:2025` · ASVS V1 · `CWE-89`, `CWE-564`

```typescript
// The builder is safe; the raw escape hatch defeats it.
await knex("users").whereRaw(`email = '${email}'`);
```

Audit `.raw`, `.extra`, `text`, `RawSQL`, `$queryRawUnsafe`, and `whereRaw`. Use the builder or
bind arguments. The wrong fix is banning every raw query: some valid SQL needs one. Make raw
SQL reviewable, parameterized, and identifier-allowlisted.

## “It was safely inserted, so stored data is trusted”

`A05:2025` · ASVS V1 · `CWE-89`

A saved report definition, imported column name, or admin label may be interpolated weeks later.
That is second-order injection. Validate at write and at the later sink, because old rows,
imports, and another service may bypass the first validator. A database row is data, not a
trusted code fragment.

## “A UUID prevents IDOR”

`A01:2025` · ASVS V8 · `CWE-566`

Opaque IDs reduce guessing. They do not enforce ownership. An attacker gets an ID from an export,
log, notification, or timing side channel and calls the endpoint. Put tenant and actor scope in
the query, or enforce it with RLS. Test a known ID belonging to another tenant.

## “Every handler adds `WHERE tenant_id = ?`”

`A01:2025` · ASVS V8 · `CWE-566`

The next handler will forget it, and a background job may never have had a tenant in its API.
Make the repository require a tenant context and use RLS as an engine-level backstop. Do not
make `tenant_id` optional “for internal callers”; create a separate, reviewed maintenance role.

## “We strip `$` keys from Mongo input”

`A05:2025` · ASVS V2 · `CWE-943`

Operator injection is structural, not quote-based. Nested objects, dotted paths, arrays, and
new operators defeat a partial sanitizer. Parse a closed schema and construct the filter from
typed fields. In particular, never query a password field with user input; verify a password hash
in application code.

## “One database user is simpler”

`A02:2025` · ASVS V13 · `CWE-250`

The migration owner becomes the web process. SQL injection can then alter schema, create users,
and erase audit rows. Use a NOLOGIN owner, a migration role, and a runtime role with named DML
grants. The runtime account must not have DDL, `FILE`, or superuser rights.

## “Disk encryption protects the database”

`A04:2025` · ASVS V11, V14 · `CWE-311`

TDE protects a stolen disk or snapshot. It does not protect rows returned through a valid
connection, a SQL injection, a DBA session, a replica, or an unencrypted dump. Choose
application-level AEAD when the database itself is in the threat model. State the gap instead of
calling all encryption “at rest.”

## “Deterministic encryption hides the value”

`A04:2025` · ASVS V11, V14 · `CWE-311`

Equal plaintext produces equal ciphertext. On country, status, or boolean columns, frequency
analysis often identifies every value. Use randomized AEAD and a keyed HMAC lookup column if
equality search is required. That index still leaks equality; document the tradeoff.

## “The pool makes RLS context global”

`A01:2025` · ASVS V8 · `CWE-566`

A session-level tenant setting stays on the physical connection after the request. The next
tenant receives the previous context. Set it transaction-locally (`set_config(..., true)`),
commit/rollback every request, and test connection reuse. Run the app as a role subject to RLS;
the owner bypasses it unless `FORCE ROW LEVEL SECURITY` is enabled.

## “N+1 is only a performance bug”

`A06:2025` · ASVS V2 · `CWE-770`

An endpoint returning 100 invoices and querying each customer's row consumes 101 connections or
queries per request. An attacker repeats it and exhausts the pool, causing an availability
incident. Eager-load deliberately, cap page size, and enforce query-count tests. Do not blindly
eager-load every relation — that can create a larger Cartesian result and a different DoS.

## “Backups are internal”

`A04:2025`, `A09:2025` · ASVS V14, V16 · `CWE-311`, `CWE-778`

Object storage, restore environments, replicas, and dump operators are all exfiltration paths.
Encrypt backups, separate key access, restrict restore, redact non-production copies, test
restores, and log backup/restore events outside the database credential's control.

## “Audit every statement”

`A09:2025` · ASVS V16 · `CWE-778`

Unbounded audit can multiply storage and write latency until operators disable it. Scope native
and application audit to sensitive reads, exports, DDL, grants, and logins; set retention and
alert thresholds. Say what it cannot answer: database-native audit may know the role but not the
end-user unless the application propagates that context.

## “The migration is just deployment plumbing”

`A08:2025` · ASVS V13, V15

Dropping a column, changing grants, or running an unbounded update changes confidentiality,
integrity, or availability. Require a second review for destructive DDL and grants, row-count
assertions for data changes, and a two-phase removal plan. Never validate a migration only by
whether it runs on an empty database.
