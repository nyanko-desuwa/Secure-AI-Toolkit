# Scalability Skill

Secure scalability is controlled work, not merely more workers. The common failure is an omitted
limit: a request fans out to 10,000 calls, a cache grows by caller-chosen keys, or each replica gets
a full rate allowance. A dependency outage then causes retries and autoscaling to amplify the outage.

## Purpose

This skill gives an AI reviewer a repeatable way to find growth, identify the security boundary, and
state the cost of a fix. It covers S1-S8 in [SKILL.md](SKILL.md), with TypeScript and Python code.
It does not execute load tests or inspect a deployed system.

## File Layout

```text
SKILL.md                         workflow, failures, boundaries, when NOT to use
README.md                        this file
checklist.md                     actionable verification
best-practices.md                patterns with vulnerable/fixed pairs
common-mistakes.md               wrong fixes and why they fail
troubleshooting.md               measurements and incident diagnosis
prompts.md                       review prompts and anti-patterns
references/
  standards-mapping.md           OWASP, API4, ASVS, verified CWE map
  capacity-formulas.md           units, budgets, sample calculations
  cache-and-limits.md            cache and distributed-limit controls
  dependency-protection.md       pools, breakers, retries, autoscaling
examples/README.md               eight runnable before/after pairs
```

## How to Use

For a design, start with the failure table in `SKILL.md`, draw trust and capacity boundaries, then
work `checklist.md`. For code, ask for the per-request denominator: queries, calls, bytes, in-flight
operations, and retained entries. For an incident, use `troubleshooting.md` and compare steady-load
measurements before changing limits.

A useful review request is:

```text
Review this service with skills/architecture/scalability. Find S1-S8 failures. For each, name the
resource that grows, the caller or dependency that drives it, the hard limit and its measured basis,
the full behavior, the security boundary, runtime cost, and a TypeScript or Python fixed pair. Map
only applicable findings to OWASP Top 10 2025, API4:2023, ASVS chapters, and verified CWEs.
```

## Configuration

There is no build step or package configuration. The examples list their runtime commands. Values
such as `MAX_IN_FLIGHT = 32`, `MAX_PAGE = 100`, `MAX_CACHE_BYTES = 64 MiB`, and a five-second total
request budget are illustrative. Replace them from observed p99 cost, dependency quota, memory
headroom, and maximum replica count.

## Security Boundaries

- A gateway can enforce a coarse body or actor limit, but the application must enforce limits on
  internal routes, decompression output, database rows, and downstream fan-out.
- A cache is a shared principal boundary. Its key and population policy must preserve tenant and
  authorization context; encryption does not repair a wrong key.
- A distributed limiter is a quota boundary. Atomicity and trusted identity must hold across all
  replicas and regions.
- A pool or semaphore is a dependency boundary. Its budget must be divided across replicas and
  reserved for health and administrative work.
- An autoscaler is a control loop, not an authorization control. It must not increase a caller's
  business quota or bypass load shedding.

## Runtime Costs

Every control has a cost. Semaphores add waiting and timeout errors. Shared limiters add network
latency and a store dependency. Cache keys with tenant and representation dimensions reduce hit rate.
Thin responses and batching trade CPU or latency for fewer bytes or round trips. Circuit breakers
may reject work while a dependency is recovering. More replicas add memory, connections, and cache
cold starts. State these costs and monitor them.

## Limitations

- Source review cannot prove effective gateway limits, cgroup limits, replica count, database quota,
  cache eviction, or alert routing. Mark those claims unverified until exercised in deployment.
- Capacity formulas are approximations. Queueing behavior, burstiness, GC, lock contention, and
  dependency variance require load tests.
- A bounded design can still be slow or incorrect. This skill does not replace query-plan analysis,
  authorization tests, or a dependency's service-level contract.
- Cache invalidation and policy revocation are domain-specific. A TTL is a staleness window, not an
  authorization proof.
- Autoscaling differs by platform. Verify metric semantics, stabilization, cooldown, and max replicas
  in the running configuration.

## Security Notes

Broken examples are labelled `Vulnerable:` and must not be copied. The examples use synthetic IDs,
placeholder URLs, and no credentials. Load tests should run only against systems you own or are
explicitly authorized to test. Metrics and cache dumps can contain tenant IDs and personal data;
restrict access and redact labels.

## References

See [references/standards-mapping.md](references/standards-mapping.md),
[references/capacity-formulas.md](references/capacity-formulas.md),
[references/cache-and-limits.md](references/cache-and-limits.md), and
[references/dependency-protection.md](references/dependency-protection.md).
