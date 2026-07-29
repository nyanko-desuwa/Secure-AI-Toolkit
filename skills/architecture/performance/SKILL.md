---
name: performance
description: 'Resource lifetime, memory leaks, and limits. Use when a process grows until it is killed, a cache or queue is unbounded, connections or listeners accumulate, or throughput needs measuring. Triggers: "memory leak", "OOM", "OOMKilled", "profiling", "cache", "backpressure", "goroutine leak", "rò rỉ bộ nhớ", "hiệu năng", "tối ưu".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Performance and Resource Lifetime

This skill answers one question about every piece of code it reads:

> What did this acquire, who owns it, and when is it released?

It is not a micro-optimisation guide. Memory leaks, unbounded caches, connection
exhaustion, listener accumulation, and dropped background tasks are one failure with five
names: something is acquired per unit of work and never released, so the process degrades
until the kernel kills it.

Treat that as a security property. An attacker who can drive allocation takes the service
down with no credentials - `A06:2025` Insecure Design, `API4:2023` Unrestricted Resource
Consumption, `CWE-400`.

## When to Use

- RSS climbs across a deploy and never comes back down
- A container is `OOMKilled`, or exit code 137 appears in the pod events
- Reviewing code that adds a cache, a queue, a pool, a listener, or a background task
- A handler reads a whole request body, file, or result set into memory
- Latency degrades with uptime rather than with load
- Choosing limits: page size, body size, pool size, queue depth, retry budget

## The Eight Leak Shapes

Every leak reviewed so far fits one of these. Names are used consistently across the
supporting files.

| # | Shape | Signal | CWE |
|---|---|---|---|
| L1 | Unbounded cache | Map keyed by user input, no max size or TTL | CWE-401, CWE-770 |
| L2 | Listener / subscription accumulation | `MaxListenersExceededWarning`, duplicate handler calls | CWE-401 |
| L3 | Connection and handle exhaustion | Pool per request, handle not closed on the error path | CWE-772 |
| L4 | Timer and background task leaks | `setInterval` never cleared, dropped tasks, blocked goroutines | CWE-772, CWE-400 |
| L5 | Closure capture and accidental retention | Detached DOM nodes, reference cycles, large captured graphs | CWE-401 |
| L6 | Request-scoped state stored globally | Module-level dict keyed by session, thread local on a pooled thread | CWE-401 |
| L7 | Large payload read fully into memory | `read()` on an unbounded body, whole result set loaded | CWE-770, CWE-789 |
| L8 | Unbounded queue or buffer | Producer faster than consumer, no backpressure | CWE-400, CWE-770 |

Details and fixes: [best-practices.md](best-practices.md).

## Workflow

### 1. Inventory acquisitions

Read the change and list what it acquires: allocations that outlive the call, cache
entries, sockets, file handles, cursors, subscriptions, timers, tasks, goroutines, locks.
For each one name the owner and the release point. If either is missing, that is the
finding - you do not need a profiler to report it.

### 2. Bound every acquisition

Anything sized by input needs an explicit maximum: page size, body size, cache entries,
queue depth, concurrency, retry count. A missing limit is `A02:2025` when a limit exists
and is unset, and `A06:2025` when the design never had one. See
[best-practices.md](best-practices.md#bounds-are-the-control).

### 3. Release on the error path

The happy path usually closes. Check the throw, the early return, the cancellation, and
the timeout. `with`, `try/finally`, `defer`, and `using` exist because manual release is
where this goes wrong.

### 4. Measure before optimising

State what you measured, under what load, and for how long. Do not tune from a guess. If
you have no measurement, say so and give the command that would produce one.

### 5. Diagnose, do not guess

Baseline, steady load, snapshot, compare retained sets, look for a growing retainer.
A single snapshot cannot tell a leak from a warm cache. Runnable commands per runtime:
[troubleshooting.md](troubleshooting.md).

### 6. Report

Per finding: leak shape, location, what grows per unit of work, what an attacker can do
to accelerate it, the fix, and the limit chosen with its reasoning. "Add a cap" is not a
fix; "cap at 10 000 entries with a 5 minute TTL, sized from p99 active users" is.

## Severity

Rank by whether an unauthenticated caller can drive the growth, and by how fast.

- **Critical** - unauthenticated request grows a global structure with no bound. One
  attacker takes down the process. Or a request-scoped value leaks across users (L6).
- **High** - authenticated caller drives unbounded growth; or a leak that reaches the
  memory limit in normal traffic within a deploy cycle.
- **Medium** - growth bounded by something else (disk, table size), or slow enough that a
  weekly deploy hides it. Still a finding: the bound is accidental.
- **Low** - bounded and correct, but the limit is undocumented or unmonitored.

A leak whose only trigger is an operator action is not critical. Say which it is.

## Related Skills

- `owasp-security` - the standards map these findings cite
- `database-security` - N+1 queries, cursors, statement timeouts
- `scalability` - capacity planning once the leaks are gone
- `api-design` - pagination contracts and body size limits

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - the eight shapes, with fixes
- [common-mistakes.md](common-mistakes.md) - including the wrong fixes people reach for
- [troubleshooting.md](troubleshooting.md) - runnable diagnosis per runtime
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - standards, version-pinned
- [examples/](examples/) - eight vulnerable/fixed pairs
