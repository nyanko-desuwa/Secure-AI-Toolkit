# Injection Standards for the Data Layer

Standards and weakness IDs cited by this skill. Verified 2026-07-28 against the sources at the
bottom of this file.

## OWASP Top 10 2025 - the categories that apply

The 2025 edition is not a renumbering of 2021. Injection moved from A03 to A05. Citing
"A03 Injection" in 2025 terms points at Software Supply Chain Failures instead.

| Category | Why the data layer is in scope |
|---|---|
| A05:2025 Injection | SQL, NoSQL, ORM raw fragments, and query-object operator injection |
| A01:2025 Broken Access Control | Tenant and ownership scoping, cross-tenant reads, IDOR on primary keys |
| A04:2025 Cryptographic Failures | Encryption at rest, column encryption, TLS to the database, backups |
| A02:2025 Security Misconfiguration | Default database accounts, permissive grants, public network binding |
| A09:2025 Security Logging and Alerting Failures | No audit of sensitive reads, no alert on bulk export |
| A06:2025 Insecure Design | Designing tenant isolation as a rule the caller must remember |

For API surfaces, OWASP API Security Top 10 2023 adds two that land in the data layer:
API1 Broken Object Level Authorization (the query is not scoped to the actor) and
API4 Unrestricted Resource Consumption (unbounded result sets, N+1 amplification).

Source: <https://owasp.org/Top10/2025/> · <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>

## OWASP ASVS 5.0.0 - chapters to verify against

ASVS 5.0.0 was released 2025-05-30. It is a restructure of 4.0.3, so 4.x requirement IDs do
not carry over. This skill cites chapters, not requirement numbers. Pull requirement text from
<https://github.com/OWASP/ASVS> if you need the precise statement.

| Chapter | Data-layer relevance |
|---|---|
| V1 Encoding and Sanitization | Query parameterization, escaping for the query interpreter |
| V2 Validation and Business Logic | Type and shape checks on input before it reaches a query object |
| V8 Authorization | Where the access decision is enforced - route, repository, or engine |
| V11 Cryptography | Algorithm and key choices for column or application-level encryption |
| V12 Secure Communication | TLS between application and database, certificate verification |
| V13 Configuration | Credentials, connection strings, database role configuration |
| V14 Data Protection | Sensitive data at rest, retention, backups, PII handling |
| V16 Security Logging and Error Handling | Audit trails, database error messages reaching clients |

Do not claim an ASVS level you have not verified requirement by requirement.

## CWE entries

| CWE | Name | Where it shows up here |
|---|---|---|
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Any string-built SQL |
| CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | NoSQL operator injection, query-object tampering |
| CWE-564 | SQL Injection: Hibernate | HQL/JPQL built by concatenation |
| CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key | Missing tenant or owner predicate |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Mass assignment through an ORM |
| CWE-250 | Execution with Unnecessary Privileges | App credential holding DDL or superuser |
| CWE-311 | Missing Encryption of Sensitive Data | Unencrypted column, unencrypted backup |
| CWE-312 | Cleartext Storage of Sensitive Information | Tokens or PII stored as plain columns |
| CWE-319 | Cleartext Transmission of Sensitive Information | Database connection without TLS |
| CWE-522 | Insufficiently Protected Credentials | Connection string in source or a world-readable file |
| CWE-770 | Allocation of Resources Without Limits or Throttling | Unbounded result sets, N+1 fan-out |
| CWE-778 | Insufficient Logging | No record of who read sensitive rows |

Source: <https://cwe.mitre.org/>

## What each control actually maps to

A shorthand for citing findings consistently.

| Finding | Cite |
|---|---|
| f-string / template literal in SQL | A05:2025 · CWE-89 · ASVS V1 |
| Interpolated `ORDER BY` or column name | A05:2025 · CWE-89 · ASVS V1 |
| `LIKE` pattern with unescaped wildcards | A05:2025 · CWE-89 (injection) or A06 (ReDoS-style cost) |
| Request body reaching a Mongo filter untyped | A05:2025 · CWE-943 · ASVS V2 |
| ORM raw escape hatch with interpolation | A05:2025 · CWE-89 or CWE-564 · ASVS V1 |
| Stored value interpolated later | A05:2025 · CWE-89 · ASVS V1 (second-order) |
| Mass assignment through model create/update | A01:2025 · CWE-915 · ASVS V2 |
| Query missing a tenant predicate | A01:2025 · CWE-566 · ASVS V8 |
| App credential can `DROP TABLE` | A02:2025 · CWE-250 · ASVS V13 |
| No TLS to the database | A04:2025 · CWE-319 · ASVS V12 |
| Unencrypted backup in shared storage | A04:2025 · CWE-311 · ASVS V14 |
| No audit record for a bulk export | A09:2025 · CWE-778 · ASVS V16 |

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP SQL Injection Prevention Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- OWASP Query Parameterization Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html>
- CWE - <https://cwe.mitre.org/>

All URLs checked 2026-07-28.
