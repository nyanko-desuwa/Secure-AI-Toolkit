# Database Security

## Purpose

A safe-looking query can still leak every tenant through an interpolated sort column, a Mongo
operator object, a forgotten scope, or a database credential that owns the schema. This skill
covers the data layer from query construction through roles, RLS, encryption, backup, audit, and
migration review.

It is guidance, not executable code. An assistant reads `SKILL.md`, traces data to query sinks,
classifies each dynamic component, checks the database boundary, and verifies against
`checklist.md` before returning code.

## How it works

```text
SKILL.md                       workflow, severity, entry point
README.md                      this file
checklist.md                   pre-return verification
best-practices.md              concrete patterns and limitations
common-mistakes.md             tempting wrong fixes and why they fail
troubleshooting.md             conflicts and engine constraints
prompts.md                     prompts that produce findings
references/
  injection-standards.md       Top 10, ASVS, CWE map
  privilege-model.md           PostgreSQL/MySQL roles, grants, RLS, TLS
examples/
  README.md                    eight vulnerable/fixed pairs
```

The query review separates values from syntax. Values get driver binds. Identifiers and sort
directions get finite allowlist maps. List arity is generated and bounded. Query-object fields
are type-checked. Tenant access is pushed below handlers, with RLS as the stronger boundary where
the engine supports it.

## Standards covered

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A05 Injection, A01 Broken Access Control, A04 Cryptographic Failures, A02 Security Misconfiguration, A06 Insecure Design, A08 Integrity, A09 Logging | 2026-07-28 |
| OWASP API Security Top 10 | 2023 | API1 object authorization, API4 resource consumption | 2026-07-28 |
| OWASP ASVS | 5.0.0 | V1, V2, V8, V11, V12, V13, V14, V15, V16 | 2026-07-28 |
| CWE | current entries | CWE-89, CWE-943, CWE-564, CWE-566, CWE-915, CWE-250, CWE-311, CWE-319, CWE-522, CWE-770, CWE-778 | 2026-07-28 |

This skill uses chapter-level ASVS citations. It does not invent 5.0 requirement IDs. For formal
verification, use the official ASVS CSV and choose a verification level explicitly.

## Languages and libraries

Examples use:

- Python: psycopg 3 and SQLAlchemy
- TypeScript/JavaScript: Prisma, Knex, and the MongoDB driver
- Raw PostgreSQL and MySQL SQL
- Java: JPA/Hibernate parameter binding
- PHP: PDO native prepared statements

The guarantees come from the driver operation, not the language. Confirm placeholder syntax and
prepared-statement behaviour against the version in the project.

## Configuration

None. The skill is Markdown and has no runtime dependency.

To use it, keep this repository readable by the assistant or copy the directory to the assistant's
skills location. The frontmatter limits tools to reading, searching, file editing, and web lookup.

Project-specific facts the user should supply where possible:

- database engine and version
- driver / ORM and version
- tenant model (shared schema, schema per tenant, database per tenant)
- sensitive data classes and threat model
- runtime, migration, reporting, and backup roles
- whether a managed service controls TLS, backup encryption, or audit

## Example usage

Review a diff:

```text
Review this diff with skills/core/database-security. Trace request data into psycopg,
SQLAlchemy, Prisma, Knex, and Mongo query sinks. For each finding give file:line, exploitation
path, Top 10 2025 category, ASVS chapter, CWE, and the smallest fix. Check tenant scoping and
runtime database grants too.
```

Review a migration:

```text
Review migrations/20260728_add_billing.sql as a security-relevant change. Check destructive
steps, unbounded updates, grants, role separation, RLS policies, lock/availability impact, backup
and restore assumptions, and rollback limitations. State what cannot be verified from SQL.
```

More focused prompts are in [prompts.md](prompts.md).

## What each layer protects

| Layer | Stops | Does not stop |
|---|---|---|
| Driver parameterization | Values becoming SQL syntax | Dynamic identifiers, sort direction, list arity, whole predicates |
| Strict NoSQL schema | Operator objects where strings are expected | An intentionally exposed expression operator |
| ORM | Injection in builder-generated SQL | Raw/extra/literal escape hatches, mass assignment |
| Scoped repository | Most forgotten tenant filters | A raw query that bypasses the repository |
| Row-level security | Unscoped queries under a policy-bound role | Table owners, `BYPASSRLS`, leaked session context, unsupported engines |
| Least-privilege role | Blast radius of injection and credential theft | Reading every row the role legitimately may read |
| TDE / volume encryption | Stolen disks and snapshots | SQL injection, DBA access, valid credentials |
| Application AEAD | Database, backup, and DBA reading plaintext | A compromised application holding the key |

## Limitations

- Markdown guidance has no cross-file taint analysis. Second-order injection often needs SAST or
  manual tracing across jobs and services.
- ORM method names and safety guarantees change. Verify the pinned version before declaring an
  escape hatch safe.
- RLS examples are PostgreSQL-specific. MySQL has no native RLS; scoped views or a repository are
  weaker substitutes.
- Application encryption examples do not design a full key hierarchy, rotation service, or
  recovery ceremony. Use a managed KMS and have the design reviewed.
- This skill cannot prove production grants, TLS negotiation, certificate verification, backup
  key custody, restore success, or audit retention from application code alone.
- N+1 detection needs runtime query-count tests. Static review finds likely fan-out, not its actual
  cost under production cardinality.
- No coverage of Oracle, SQL Server, DynamoDB, Cassandra, Elasticsearch query DSL, stored
  procedures, replication protocol hardening, or database patch management.

## Security notes

Files in this skill contain deliberately vulnerable code. Every vulnerable block is labelled and
paired with a fixed version. Do not copy the vulnerable blocks.

Placeholder credentials such as `placeholder` are intentionally non-secret. They demonstrate
syntax only and must not be deployed.

Deterministic encryption and keyed lookup columns leak equality. The skill describes them as a
tradeoff, not as equivalent to randomized encryption.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP SQL Injection Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- OWASP Query Parameterization Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html>
- OWASP Database Security Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html>
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- CWE-943 — <https://cwe.mitre.org/data/definitions/943.html>
- CWE-564 — <https://cwe.mitre.org/data/definitions/564.html>
