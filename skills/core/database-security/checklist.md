# Database Security Checklist

Mark each item pass, fail, or not applicable. An N/A needs a reason. Controls map to OWASP Top
10 2025, ASVS 5.0, and CWE where applicable.

## Query construction - A05 · ASVS V1, V2

- [ ] Every SQL value uses a driver bind; no f-string, template literal, `+`, `%`, or `.format`
- [ ] ORM escape hatches (`text`, `raw`, `extra`, `RawSQL`, `$queryRawUnsafe`, `whereRaw`) are
      absent or reviewed with binds
- [ ] Dynamic table and column names come from a server-owned allowlist map
- [ ] Sort direction is an allowlist, not a boolean or raw string
- [ ] `IN` lists use generated placeholders or an array bind and have a maximum length (`CWE-770`)
- [ ] `LIKE` values are bound; `%`, `_`, and the escape character are escaped where literal search
      is intended; leading wildcards and expensive searches are bounded
- [ ] Dynamic `WHERE` clauses are composed only from fixed server-owned fragments
- [ ] Stored values that later become query text are validated again at the later sink
- [ ] SQL error details and query text do not reach the client

## NoSQL and ORM - A05, A01 · ASVS V2, V8

- [ ] No request object is passed directly into a MongoDB-style filter
- [ ] Query fields have explicit types; unknown keys are rejected (`CWE-943`)
- [ ] `$where`, `$expr`, `mapReduce`, and equivalent expression operators cannot receive input
- [ ] ORM create/update data is an explicit DTO, not `req.body` or a model dump (`CWE-915`)
- [ ] Relations are loaded deliberately; N+1 fan-out has a query count or result-size bound
      (`CWE-770`, API4:2023)

## Authorization and tenancy - A01 · ASVS V8

- [ ] Every read, write, and delete is scoped to actor and tenant server-side (`CWE-566`)
- [ ] Tenant ID comes from authenticated context, never a body, query parameter, or path alone
- [ ] Repository APIs do not expose an unscoped query/session to handlers
- [ ] RLS is enabled and forced where the engine supports it; `USING` and `WITH CHECK` both exist
- [ ] RLS context is set per transaction and cleared by transaction end in pooled connections
- [ ] A direct cross-tenant read and write test returns zero rows / an error
- [ ] A UUID or opaque ID is not treated as authorization; it is only an enumeration defence

## Roles and migrations - A02, A01 · ASVS V8, V13, V15

- [ ] Runtime, migration, reporting, and owner roles are separate
- [ ] Runtime role cannot `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, grant, or change roles (`CWE-250`)
- [ ] Grants name the schema and tables; no application `GRANT ALL` or superuser
- [ ] Default privileges cover future tables, sequences, and functions
- [ ] Append-only audit/ledger tables deny runtime `UPDATE` and `DELETE`
- [ ] Migration runs with the migration credential, not the runtime credential
- [ ] Destructive migrations are two-phase and have rollback/data-retention plans
- [ ] Data migrations require a predicate, row-count assertion, and second review

## Encryption and connections - A04 · ASVS V11, V12, V14

- [ ] Volume/TDE, column, and application encryption are mapped to a stated threat
- [ ] Application-level encryption uses an AEAD primitive and nonce/IV rules (`CWE-311`)
- [ ] Deterministic encryption is documented as equality leakage, especially on low-cardinality data
- [ ] Encryption keys are outside the database and rotate through a KMS/secret manager
- [ ] PostgreSQL uses `sslmode=verify-full`; MySQL uses `VERIFY_IDENTITY` or equivalent (`CWE-319`)
- [ ] Certificate and hostname verification are on; TLS downgrade fails closed
- [ ] Connection strings are not in source, images, shell history, or logs (`CWE-522`)
- [ ] Credentials rotate without a source change or full application rebuild

## Backups and audit - A04, A09 · ASVS V14, V16

- [ ] Backups and snapshots are encrypted with separately protected keys
- [ ] Backup creation and restore privileges are restricted and logged
- [ ] Restores are tested; production data is redacted before non-production use
- [ ] Sensitive reads, bulk exports, DDL, grants, and logins produce tamper-resistant audit events
- [ ] Audit destination cannot be modified by the application database credential
- [ ] Audit volume, retention, and alert thresholds are explicit; cost is accepted

## Before returning

- [ ] Relevant tests include malicious values, unknown NoSQL keys, cross-tenant IDs, and empty/huge lists
- [ ] Query count and result-size limits are tested for list and relation endpoints
- [ ] Migration was reviewed as a security-relevant change
- [ ] Unverifiable runtime settings are stated plainly, not marked pass
