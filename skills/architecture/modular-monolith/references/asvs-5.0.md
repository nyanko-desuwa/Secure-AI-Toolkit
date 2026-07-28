# OWASP ASVS 5.0 Mapping

ASVS 5.0.0 was released 2025-05-30. Verified 2026-07-28 against
<https://owasp.org/www-project-application-security-verification-standard/>.
Citations are chapter-level only. Do not invent or copy requirement IDs.

| Chapter | Modular-monolith use |
|---|---|
| V8 Authorization | Actor-scoped commands/queries, tenant/resource predicates, consumer re-authorization, tenant-aware cache keys |
| V15 Secure Coding and Architecture | Module ownership, dependency direction, contracts, data compartmentalisation, transaction/outbox design, bounded concurrency |
| V16 Security Logging and Error Handling | Rollback/cleanup, retry exhaustion, poison messages, outbox lag, queue rejection, connection/listener metrics |

Related where directly applicable:

- V2 Validation and Business Logic: command shape, collection/range bounds, invariants, duplicate/idempotent behavior.
- V4 API and Web Service: public adapter request/response constraints.
- V13 Configuration: effective database grants, pool size, timeouts, queue/cache limits.
- V14 Data Protection: minimal contract/event fields and sensitive diagnostics.

A chapter citation does not claim ASVS level compliance. Verify the official 5.0 requirement set and
the running deployment for a formal assessment.

## Sources

- OWASP ASVS project — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP ASVS repository — <https://github.com/OWASP/ASVS>
