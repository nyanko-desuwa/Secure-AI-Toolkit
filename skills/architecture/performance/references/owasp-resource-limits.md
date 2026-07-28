# OWASP Mapping for Resource Limits

Which category a resource-lifetime finding belongs to, and how to word it so it survives
review. Verified 2026-07-28.

Sources:

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://owasp.org/www-project-application-security-verification-standard/>

## Why these findings are security findings

Availability is one of the three properties. A caller who can make the process allocate
without bound can end the service without a credential, and the request that does it looks
like every other request. That is the argument for filing a missing bound as a vulnerability
rather than as technical debt.

Two of the leak shapes are confidentiality bugs as well. Request-scoped state in a global,
and a shared cache keyed without tenant identity, both serve one user's data to another. File
those under access control, not resource consumption.

## Top 10 2025

The 2025 edition is not a renumbering of 2021. Injection moved from A03 to A05; A03 and A10
are new. There is no dedicated resource-consumption category, so use these two.

| Category | Use it when |
|---|---|
| A06:2025 Insecure Design | The design never had a limit. No pagination cap, no queue depth, no eviction policy, no timeout. Implementation care cannot fix it |
| A02:2025 Security Misconfiguration | A limit exists in the platform and is unset or left at an unsafe default. Unlimited `MaxOpenConns`, no `client_max_body_size`, no container memory limit, debug-level allocation tracking left on |
| A01:2025 Broken Access Control | Cross-request or cross-tenant data exposure from shared state or an untenanted cache key |
| A09:2025 Security Logging and Alerting Failures | The growth is invisible. No metric on cache size, queue depth, or memory; OOMKill is discovered from a customer report |
| A10:2025 Mishandling of Exceptional Conditions | The error path leaks the resource. A handle closed only on success, a lock released only after the work, a pool connection held by a failed request |

The A06/A02 distinction is worth getting right, because it decides who fixes it. A06 goes to
whoever owns the design; A02 goes to whoever owns the deployment.

## API Security Top 10 2023

| Category | Use it when |
|---|---|
| API4:2023 Unrestricted Resource Consumption | The primary citation for this skill. No cap on request size, page size, upload size, concurrency, or third-party quota spend |
| API6:2023 Unrestricted Access to Sensitive Business Flows | The flow is used correctly but at a harmful scale. Rate limiting reduces API4 to acceptable; it does not solve API6 |
| API1:2023 Broken Object Level Authorization | Reached through a cache key that omits the actor |

API4 is the one to quote when asking for a limit. It is explicit that the API should have
limits on execution timeouts, maximum allocable memory, number of file descriptors, number of
processes, request payload size, requests per client, and number of records returned per
request. That list is a checklist on its own.

GraphQL shifts API4 onto query depth and complexity. Cap both. A nested query is a denial of
service that arrives as one valid HTTP request, and batched operations multiply the cost of a
per-request rate limit.

## ASVS 5.0.0

Version 5.0.0, released 2025-05-30. Chapter-level citations only — 5.0 renumbered
requirements, so a recalled ID from 4.x means something different or nothing at all.

| Chapter | Relevance here |
|---|---|
| V2 Validation and Business Logic | Input-derived sizes are validated and bounded: page size, array length, requested range |
| V13 Configuration | Platform limits are set deliberately: body size, pool size, timeouts, runtime memory ceiling |
| V16 Security Logging and Error Handling | Failures release resources, errors are handled rather than swallowed, and resource events are logged |
| V5 File Handling | Upload size caps and decompression bounds |
| V8 Authorization | The cache-key and shared-state cases, where the failure is unauthorized read |

For requirement-level verification, pull current text from <https://github.com/OWASP/ASVS>.
Citing the chapter is honest; inventing `V2.4.7` is not.

## Wording a finding

A resource finding is credible when it names what grows, per what, and who can drive it.

Weak: "the cache is unbounded, which could cause memory issues".

Strong: "`_render_cache` in `render.py:14` gains one entry per distinct `params` value, with
no eviction. `params` is unvalidated request input, so an unauthenticated caller adds entries
at request rate. At the observed p99 entry size of 4 KB, 250 000 requests reaches the 1 Gi
container limit and the process is OOMKilled. A06:2025, API4:2023, CWE-770."

Four things make the difference: the unit of growth, the input that drives it, the attacker's
starting position, and the ceiling it hits.

## Severity, and when not to escalate

| Severity | Condition |
|---|---|
| Critical | Unauthenticated caller drives unbounded growth in a global structure, or request-scoped data crosses users |
| High | Authenticated caller drives it, or normal traffic reaches the limit within a deploy cycle |
| Medium | Growth bounded by something incidental — table size, disk, an upstream quota — or slow enough that routine deploys mask it |
| Low | Bounded and correct, but the limit is undocumented or unmonitored |

Do not escalate on category name. An unbounded cache keyed by a value only an operator can
set is not critical. Say which precondition you checked and which you assumed.

## What this mapping does not cover

- Rate limiting design. Per-actor and per-IP limits belong in an API or gateway skill; this
  skill covers what happens to memory when the limit is absent.
- Cost control. A third-party quota burned by a retry storm is a real incident and maps to
  API4, but the financial controls are out of scope.
- Compliance frameworks. No ISO 27001, SOC 2, or PCI DSS mapping here.
