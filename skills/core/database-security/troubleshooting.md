# Troubleshooting Database Security

What to do when the secure data-layer pattern does not fit cleanly.

## The driver’s placeholder syntax is unclear

Do not guess. `%s`, `$1`, `?`, `:name`, and `@name` are not interchangeable.

- psycopg 3: `%s` for values; a sequence or mapping is the second `execute` argument.
- SQLAlchemy `text()`: `:name` and a mapping.
- PostgreSQL protocol / node-postgres: `$1`, `$2`.
- Knex raw: `?` for values, `??` for identifiers - still allowlist identifiers first.
- PDO: `?` or `:name`; disable emulated prepares where supported.
- JDBC: `?` with `PreparedStatement`; never `Statement` plus concatenation.

Read the pinned driver docs and add a malicious-value regression test. Parameterization is
`A05:2025`, ASVS V1, `CWE-89`; syntax that looks right but formats first is still injection.

## A table or column really must be dynamic

A bind cannot represent it. Map a client key to one of a finite set of server-owned identifiers.
If the set is not finite - a user-created table per account, for example - reconsider the schema.
One shared table with `tenant_id` is easier to grant, migrate, audit, and protect with RLS.

Driver quoting (`psycopg.sql.Identifier`, Knex `??`) correctly escapes an identifier but does
not authorize it. Allowlist first, quote second. `A05:2025`, ASVS V1, `CWE-89`.

## The ORM cannot express the query

Use raw SQL, but preserve the guarantees:

1. Bind every value.
2. Allowlist and quote every dynamic identifier.
3. Keep the raw fragment in one named function rather than spreading escape hatches.
4. Add a test with quotes, comments, wildcard characters, and an overlong list.
5. Scope tenant access inside that function.

“Never use raw SQL” is not a workable policy. “Every raw sink is reviewed” is. `A05:2025`, ASVS
V1, `CWE-89` / `CWE-564`.

## An empty `IN` list breaks the query

`IN ()` is invalid in many engines. Decide the semantics before building SQL. For
`WHERE id IN (...)`, an empty list usually means return no rows, so return `[]` without querying.
It must not mean “omit the predicate,” because omitting it turns an empty request into a full-table
read. Bound the list size too. `A05:2025`, `A06:2025`, ASVS V1/V2, `CWE-89`, `CWE-770`.

## Users need wildcard search

Do not escape `%` and `_` if wildcard semantics are the feature. Bind the pattern, require a
minimum literal length, cap result count and query time, and decide whether leading wildcards are
allowed. Add a suitable full-text index if substring search is a requirement.

Binding handles `CWE-89`; bounds handle `CWE-770`. They solve different problems.

## The framework strips unknown Mongo operators

Verify the exact version and configuration. Then type-check anyway. Middleware that removes `$`
keys does not guarantee a field is a string and may miss nested objects, dotted paths, or newly
introduced operators. Closed schemas are the durable control. `A05:2025`, ASVS V2, `CWE-943`.

## RLS is unavailable

MySQL and some managed engines have no equivalent. Build a tenant-scoped repository that does not
expose a raw session, grant the app only to scoped views where practical, and test a known
cross-tenant primary key on every operation. State the limitation: application enforcement is
weaker because one bypass can omit it. `A01:2025`, ASVS V8, `CWE-566`.

## RLS breaks migrations or background jobs

Do not weaken the runtime policy or make an optional tenant mean “all tenants.” Use a separate,
short-lived maintenance role and make the cross-tenant operation explicit. For PostgreSQL,
remember that owners and `BYPASSRLS` roles evade policies; a background worker using either has
an unrestricted credential. Audit its use. `A01:2025`, `A02:2025`, ASVS V8/V13, `CWE-250`.

## RLS leaks between requests

The tenant was probably stored on the session behind a pool. Set context transaction-locally,
commit or roll back every request, reset connections on checkout, and test by alternating tenant
A and B on a pool of size one. `A01:2025`, ASVS V8, `CWE-566`.

## Least privilege blocks a deploy

Do not add `GRANT ALL` to the runtime role. The usual causes are:

- The migration created a table as the wrong owner.
- `ALTER DEFAULT PRIVILEGES` was set for a different creator role.
- A sequence needs `USAGE` even though the table has `INSERT`.
- A function needs `EXECUTE`; its security-definer behaviour needs separate review.

Fix the grant as the migration owner, then add an integration test that connects as the runtime
role and proves DML works while DDL fails. `A02:2025`, ASVS V13, `CWE-250`.

## TLS cannot be enabled immediately

Do not silently accept plaintext. State where the connection travels, isolate it to a private
network, add server-side enforcement and certificate verification as a tracked blocker, and fail
the deployment if the route becomes public. A private network reduces exposure; it does not
replace authenticated encryption. `A04:2025`, ASVS V12, `CWE-319`.

## Credential rotation drops connections

Use two valid credentials during a rotation window: issue the new credential, update pool
creation, drain old connections, then revoke the old one. Short-lived dynamic credentials avoid
coordinated rotations, but the pool must renew before expiry. Never log the URI while debugging.
`A04:2025`, ASVS V13/V14, `CWE-522`.

## Application encryption prevents querying

That is a real limitation, not a library bug.

- Exact equality: add a keyed HMAC lookup index and keep the value randomized.
- Low-cardinality value: equality leakage may reveal it; do not use deterministic encryption.
- Range, sort, prefix, or substring: redesign the feature, retain a non-sensitive derived field,
  or keep the query inside a more trusted database boundary.

Never claim deterministic encryption is semantically secure. It reveals equality by design.
`A04:2025`, ASVS V11/V14, `CWE-311`.

## Audit is too expensive

Measure statement volume, storage, and latency; then scope. Keep DDL, grants, authentication,
bulk exports, and reads of regulated tables. Sample only events whose loss is accepted and
explicit. Native audit lacks end-user context unless you propagate it; application audit can be
bypassed by raw database access. Use both where “who read what” is a requirement. `A09:2025`,
ASVS V16, `CWE-778`.

## A destructive migration is already merged

Do not run it because it passed CI. Check production row counts, locks, backups, and restore time.
Split it into expand/migrate/contract steps, deploy the read path before dropping anything, and
require a named approver for the final contract step. An empty test database proves syntax, not
safety. `A08:2025`, ASVS V13/V15.
