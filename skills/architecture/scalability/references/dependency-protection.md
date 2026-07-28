# Dependency Protection

A scaling service must protect dependencies as carefully as it protects itself. More replicas can
multiply database connections, provider calls, queue consumers, cache fills, and retry attempts.

## Required Controls

- Process-owned clients and pools, created once and closed on shutdown.
- Per-dependency semaphore or max-in-flight budget before a call is created.
- Connect, read, and total deadlines; cancellation closes the underlying operation.
- Pool acquisition timeout and a reserved capacity slice for health, migrations, and operators.
- One retry owner with a small attempt cap, jitter, idempotency, and a total deadline.
- Circuit breaker plus bounded half-open probes; a breaker does not replace a semaphore.
- Autoscaler maximum derived from the tightest downstream quota, with stabilization and drain.
- Metrics for calls, failures, timeout class, retries, breaker state, in-flight, queue age, pool
  wait, connections, and useful completed work.

## N+1 and Connection Arithmetic

N+1 is both a latency multiplier and a connection pressure multiplier. Use a join, eager load, or
batch query while retaining a server-side page cap. Assert query count at page sizes 1, 10, and 100.
Keep network calls outside database transactions; persist an intent and use an idempotency key when
an external effect is required.

Calculate at maximum replicas, not current replicas:

```text
pool_max × max_replicas + background pools + reserve < database limit
```

If this cannot hold, reduce per-pod pools, cap replicas, reduce work, or increase the database
capacity deliberately. Raising the pool without this arithmetic is an outage multiplier.

## Retry and Outage Behavior

Retry only classified transient failures and only safe or idempotent operations. A fixed cap of two
attempts, a 300 ms total retry budget, and full jitter are example starting values, not defaults.
A three-attempt policy at five layers can create 243 calls from one logical request. Avoid retrying
at every layer. When a dependency fails, admit less work and preserve capacity for recovery.

## Runtime Cost and When Not to Use

Bulkheads and semaphores add waiting and early errors. Breakers reject calls while recovery probes
run. Pool reductions can lower throughput on healthy traffic. Autoscaling caps may leave CPU unused.
These costs are intentional protection for the dependency boundary.

Do not add a breaker to a non-failing local operation, or retries to a non-idempotent write without
provider idempotency. Do not add replicas where the bottleneck is a singleton or quota-bound provider.
Do not hold a database transaction while waiting on a remote service.

## Sources

- OWASP API Security Top 10 2023, API4 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS 5.0 project — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- CWE-400 — <https://cwe.mitre.org/data/definitions/400.html>
- CWE-772 — <https://cwe.mitre.org/data/definitions/772.html>
- CWE-789 — <https://cwe.mitre.org/data/definitions/789.html>
