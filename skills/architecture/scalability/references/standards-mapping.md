# Standards Mapping

Verified 2026-07-28 against the repository brief and the linked official sources. Cite only the
categories and chapters below; do not invent ASVS requirement IDs.

## OWASP Top 10 2025

| Failure | Mapping | Why |
|---|---|---|
| Cross-tenant cache value or stale authorization disclosure | A01 Broken Access Control; ASVS V8 | Shared state returns data outside the actor's scope |
| Limit exists but gateway, pool, runtime, or autoscaler leaves it unsafe | A02 Security Misconfiguration; ASVS V13 | Deployment control is missing or ineffective |
| No bound on fan-out, queue, cache, retries, page size, or work | A06 Insecure Design; ASVS V4/V15 | Design has no capacity decision |
| Missing queue, pool, cache, limiter, or saturation alert | A09 Security Logging and Alerting Failures; ASVS V16 | Operators cannot detect the boundary failing |
| Error path retries, retains, or holds a pool/transaction | A10 Mishandling of Exceptional Conditions; ASVS V16 | Exceptional control flow bypasses release or failure policy |

## OWASP API Security Top 10 2023

`API4:2023 Unrestricted Resource Consumption` is the primary API mapping for request bytes, page
size, records, fan-out, concurrency, queue depth, timeouts, retries, and third-party quota. `API1`
may apply when cache keys omit the actor or tenant. API6 is a business-flow concern, not a substitute
for a resource limit. The application must enforce limits even when a gateway has one; internal routes,
chunked bodies, decompression, and downstream work can bypass edge controls.

## ASVS 5.0.0

- V4 API and Web Service: message/body bounds, GraphQL amount and cost limits, and API protocol
  behavior.
- V8 Authorization: tenant and actor scope in cache keys and data lookups.
- V13 Configuration: pool, proxy, timeout, runtime, worker, autoscaling, and diagnostic settings.
- V15 Secure Coding and Architecture: ownership, bulkheads, bounded concurrency, and dependency design.
- V16 Security Logging and Error Handling: cleanup, saturation, retries, alerting, and fail-closed
  error handling.

Cite chapter-level guidance unless a verified source provides a current requirement ID. Do not claim an
ASVS verification level from this skill.

## Verified CWEs

| CWE | Name | Scalability use |
|---|---|---|
| CWE-400 | Uncontrolled Resource Consumption | Amplified retries, queue growth, autoscaling outage |
| CWE-401 | Missing Release of Memory After Effective Lifetime | Cache, retained payload, or cross-request state |
| CWE-770 | Allocation of Resources Without Limits or Throttling | Missing cap on queue, cache, fan-out, or retries |
| CWE-772 | Missing Release of Resource after Effective Lifetime | Pool, connection, transaction, timer, or task |
| CWE-789 | Memory Allocation with Excessive Size Value | One input-sized body, batch, or result allocation |

Use the mechanism first: a no-limit queue is CWE-770 reaching CWE-400; a per-request pool is
CWE-772. Do not label every slow endpoint CWE-400 without identifying uncontrolled consumption.

## Sources

- <https://owasp.org/Top10/2025/> (verified 2026-07-28)
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/> (verified 2026-07-28)
- <https://owasp.org/www-project-application-security-verification-standard/> (verified 2026-07-28)
- <https://cwe.mitre.org/data/definitions/400.html>
- <https://cwe.mitre.org/data/definitions/401.html>
- <https://cwe.mitre.org/data/definitions/770.html>
- <https://cwe.mitre.org/data/definitions/772.html>
- <https://cwe.mitre.org/data/definitions/789.html>
