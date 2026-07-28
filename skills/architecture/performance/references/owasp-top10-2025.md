# OWASP Top 10 (2025) for Resource Lifetime

Current released version. Verified 2026-07-28 against
<https://owasp.org/Top10/2025/>.

The 2025 edition is not a renumbering of 2021. Injection moved to A05; A03 and A10 are new.
Resource exhaustion has no dedicated category, so this skill uses the categories below.

## A06:2025 — Insecure Design

Use A06 when the design never defined a limit or owner:

- A cache with no eviction policy
- A queue with no maximum depth or full behaviour
- An endpoint with no body or page-size cap
- Fan-out with no concurrency ceiling
- A task or goroutine with no cancellation owner
- Retries with no attempt or time budget

Implementation care cannot repair an absent decision. The control is the bound itself, with a
reason for its value and a defined behaviour when reached.

Review questions:

- What grows per request, tenant, reconnect, or retry?
- Can an unauthenticated caller drive that growth?
- What ceiling stops it before process, cgroup, or dependency exhaustion?
- Is saturation block, drop, or reject? Is that outcome visible?

## A02:2025 — Security Misconfiguration

Use A02 when the platform provides a limit and deployment leaves it unset or unsafe:

- No reverse-proxy body limit
- No container memory limit
- Go SQL `MaxOpenConns` left unlimited
- Runtime heap ceiling equal to the whole cgroup budget, with no native headroom
- Diagnostic inspector exposed on a public interface

The A06/A02 distinction identifies the owner. A06 belongs to the design owner. A02 belongs to
whoever configures the runtime or deployment. A finding may cite both when neither layer has a
bound.

## A01:2025 — Broken Access Control

Use A01 instead of treating these as ordinary performance findings:

- A shared cache key omits tenant or user identity
- Request-scoped state is stored globally or in an uncleared thread local
- A pooled worker reads the previous request's actor or tenant

The failure is unauthorized disclosure. Memory retention is secondary. Test with two users on
the same worker and assert that neither receives the other's value.

## A09:2025 — Security Logging and Alerting Failures

Resource failure is invisible when no one records:

- Cache entries or bytes
- Queue depth, rejection, and drop count
- Pool wait time and acquire failures
- Listener, task, thread, or goroutine count
- RSS and heap against their limits
- OOMKill events

A log line nobody alerts on is not an alert. Track the structure that grows, not only process
RSS, so the signal identifies an owner.

## A10:2025 — Mishandling of Exceptional Conditions

Use A10 when the success path releases and an exceptional path does not:

- File or cursor closed after work rather than by a scope guard
- Listener removed on normal completion but not disconnect
- Lock or connection held when parsing raises
- Task failure swallowed and never observed
- Cancellation treated as an error while cleanup is skipped

`with`, `try/finally`, `defer`, and `using` attach release to scope. The error path is the test
case; the happy path usually already closes.

## Reporting

A useful finding names the unit of growth and who drives it:

> `_render_cache` gains one entry per distinct request `params`, with no eviction. An
> unauthenticated caller controls `params`; at the measured p99 entry size of 4 KiB, 250,000
> entries consume about 1 GiB. A06:2025, CWE-770.

"May cause memory issues" omits the growth unit, attacker position, and limit hit.

## Severity

- Critical: unauthenticated caller drives unbounded global growth, or data crosses users
- High: authenticated caller drives it, or normal traffic reaches the limit within a deploy
- Medium: an incidental external bound exists, or routine restarts hide slow growth
- Low: correct bound exists but is undocumented or unmonitored

Do not escalate on category name alone. State which precondition was verified.

## Source

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
