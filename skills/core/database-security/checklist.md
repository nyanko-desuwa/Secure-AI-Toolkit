# Database Security Checklist

Mark each item pass, fail, or not applicable. An N/A needs a reason. Controls map to OWASP Top
10 2025, ASVS 5.0, and CWE where applicable.

## Query construction - A05 · ASVS V1, V2

- [ ] [critical] Every SQL value uses a driver bind; no f-string, template literal, `+`, `%`, or `.format`
- [ ] [critical] ORM escape hatches (`text`, `raw`, `extra`, `RawSQL`, `$queryRawUnsafe`, `whereRaw`) are
      absent or reviewed with binds
- [ ] [critical] Dynamic table and column names come from a server-owned allowlist map
- [ ] [critical] Sort direction is an allowlist, not a boolean or raw string
- [ ] [recommended] `IN` lists use generated placeholders or an array bind and have a maximum length (`CWE-770`)
- [ ] [recommended] `LIKE` values are bound; `%`, `_`, and the escape character are escaped where literal search
      is intended; leading wildcards and expensive searches are bounded
- [ ] [critical] Dynamic `WHERE` clauses are composed only from fixed server-owned fragments
- [ ] [critical] Stored values that later become query text are validated again at the later sink
- [ ] [recommended] SQL error details and query text do not reach the client

## NoSQL and ORM - A05, A01 · ASVS V2, V8

- [ ] [critical] No request object is passed directly into a MongoDB-style filter
- [ ] [critical] Query fields have explicit types; unknown keys are rejected (`CWE-943`)
- [ ] [critical] `$where`, `$expr`, `mapReduce`, and equivalent expression operators cannot receive input
- [ ] [critical] ORM create/update data is an explicit DTO, not `req.body` or a model dump (`CWE-915`)
- [ ] [recommended] Relations are loaded deliberately; N+1 fan-out has a query count or result-size bound
      (`CWE-770`, API4:2023)

## Authorization and tenancy - A01 · ASVS V8

- [ ] [critical] Every read, write, and delete is scoped to actor and tenant server-side (`CWE-566`)
- [ ] [critical] Tenant ID comes from authenticated context, never a body, query parameter, or path alone
- [ ] [critical] Repository APIs do not expose an unscoped query/session to handlers
- [ ] [critical] RLS is enabled and forced where the engine supports it; `USING` and `WITH CHECK` both exist
- [ ] [critical] RLS context is set per transaction and cleared by transaction end in pooled connections
- [ ] [critical] A direct cross-tenant read and write test returns zero rows / an error
- [ ] [recommended] A UUID or opaque ID is not treated as authorization; it is only an enumeration defence

## Roles and migrations - A02, A01 · ASVS V8, V13, V15

- [ ] [recommended] Runtime, migration, reporting, and owner roles are separate
- [ ] [critical] Runtime role cannot `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, grant, or change roles (`CWE-250`)
- [ ] [critical] Grants name the schema and tables; no application `GRANT ALL` or superuser
- [ ] [recommended] Default privileges cover future tables, sequences, and functions
- [ ] [recommended] Append-only audit/ledger tables deny runtime `UPDATE` and `DELETE`
- [ ] [recommended] Migration runs with the migration credential, not the runtime credential
- [ ] [recommended] Destructive migrations are two-phase and have rollback/data-retention plans
- [ ] [recommended] Data migrations require a predicate, row-count assertion, and second review

## Encryption and connections - A04 · ASVS V11, V12, V14

- [ ] [recommended] Volume/TDE, column, and application encryption are mapped to a stated threat
- [ ] [critical] Application-level encryption uses an AEAD primitive and nonce/IV rules (`CWE-311`)
- [ ] [recommended] Deterministic encryption is documented as equality leakage, especially on low-cardinality data
- [ ] [critical] Encryption keys are outside the database and rotate through a KMS/secret manager
- [ ] [critical] PostgreSQL uses `sslmode=verify-full`; MySQL uses `VERIFY_IDENTITY` or equivalent (`CWE-319`)
- [ ] [critical] Certificate and hostname verification are on; TLS downgrade fails closed
- [ ] [critical] Connection strings are not in source, images, shell history, or logs (`CWE-522`)
- [ ] [recommended] Credentials rotate without a source change or full application rebuild

## Backups and audit - A04, A09 · ASVS V14, V16

- [ ] [critical] Backups and snapshots are encrypted with separately protected keys
- [ ] [recommended] Backup creation and restore privileges are restricted and logged
- [ ] [recommended] Restores are tested; production data is redacted before non-production use
- [ ] [recommended] Sensitive reads, bulk exports, DDL, grants, and logins produce tamper-resistant audit events
- [ ] [recommended] Audit destination cannot be modified by the application database credential
- [ ] [recommended] Audit volume, retention, and alert thresholds are explicit; cost is accepted

## Before returning

- [ ] [critical] Relevant tests include malicious values, unknown NoSQL keys, cross-tenant IDs, and empty/huge lists
- [ ] [recommended] Query count and result-size limits are tested for list and relation endpoints
- [ ] [recommended] Migration was reviewed as a security-relevant change
- [ ] [critical] Unverifiable runtime settings are stated plainly, not marked pass
