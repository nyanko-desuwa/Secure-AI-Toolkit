# Prompts

Good prompts ask for enforcement evidence, bypass paths, and runtime cost. "Make it modular" asks
for folders.

## Discover Module Boundaries

```text
Read application entry points, imports, migrations, SQL, database grants, and background jobs.
Propose modules only where business language, authorization, data ownership, or change ownership
differs. For each module list owned tables, migrations, runtime role, public commands/queries,
events, and forbidden dependencies. State the cost of every boundary and reject splits that cut a
required atomic invariant.
```

## Audit Cross-Module Data Access

```text
For each table and ORM model, name one owning module and every reader/writer. Flag direct access by
non-owners as CWE-653/CWE-1220. Show the exact import or SQL evidence. Replace it with an
actor-scoped contract or owner-published projection and state query, mapping, and staleness cost.
```

## Design an Actor-Scoped API

```text
Design the Billing module API for approveInvoice. The signature must require an explicit verified
actor, tenant-scoped resource ID, bounded validated command, cancellation, and an allowlisted result.
Put permission, ownership, and self-approval rules inside Billing. Show HTTP, job, and event callers
using the same API. Do not use ambient current-user state.
```

## Review Transactions

```text
Trace transaction begin/commit/rollback and every module or network call between them. Report locks,
connection lifetime, tracked entities, timeout, and cleanup on error/cancellation. Keep one module
owner per transaction. If another module is required, decide whether the boundary is wrong or define
pending state, idempotency, compensation, and reader behavior.
```

## Design an Outbox

```text
Write the local transaction that stores Order and OrderPlaced.v1 outbox rows atomically. Define a
minimal payload, stable message ID, tenant scope, bounded poll batch/concurrency, retry/time budget,
poison-message state, lag metric, retention, and consumer idempotency. Test rollback and duplicate
delivery. Do not claim exactly-once effects.
```

## Audit Resource Lifetimes

```text
Find global buses, subscribe/on calls, module singletons, mutable module-level state, queues, caches,
timers, tasks, transactions, cursors, streams, and lazy iterators. For each name owner, bound, release
point, captured actor/tenant state, and behavior on error/cancellation/shutdown. Map missing bounds to
CWE-770 and missing release to CWE-772.
```

## Write Contract Tests

```text
Test the module through its public API and real persistence adapter. Cover allowed actor, denied
actor, wrong tenant, malformed/unknown input, collection limits, response allowlist, runtime DB role
grants, rollback/outbox atomicity, duplicate delivery, and forbidden imports. State what source and
tests still cannot prove about deployment.
```

## Decide against the Pattern

```text
This feature validates a small profile form, checks tenant ownership in one query, writes one table,
and has no other entry point or invariant. Explain why a modular monolith module, internal bus, and
outbox do not earn their navigation, allocation, and lifecycle cost. Return the smaller auditable
design instead.
```

## Compare with Microservices

```text
Compare a modular monolith and microservices for this measured workload and team. Evaluate
independent scaling, deployment, regulatory isolation, failure containment, latency, serialization,
retries, data ownership, consistency, observability, pool/process overhead, and on-call ownership.
Recommend extraction only if one benefit pays its permanent operational cost.
```

## Verify Before Returning

```text
Run skills/architecture/modular-monolith/checklist.md. Mark each item pass, fail, or not applicable
with one-line evidence. A folder is not proof of a boundary. A contract is not proof of authorization.
A post-save hook is not proof of durable delivery. Report residual gaps and actual measurements.
```

## Anti-Patterns

| Prompt | What it produces | Better instruction |
|---|---|---|
| "Make it modular" | Namespaces over shared state | Name owners, grants, contracts, and forbidden imports |
| "Create a module per table" | Technical slices and chatty calls | Split by invariant and business capability |
| "Share a common repository" | Optional tenant filters | One owner; actor-scoped intention methods |
| "Use an internal event bus" | Listener leaks and pre-commit effects | Name delivery need, outbox, bounds, disposer, idempotency |
| "Use one transaction" | Locks held across module calls | Name invariant; one owner or explicit pending state |
| "Make it scalable" | Unbounded queues and speculative caches | Give measured load, capacity, saturation behavior |
| "Add authorization in middleware" | Jobs and handlers bypass checks | Require actor in owning module API |
| "Return a stream for performance" | Hidden cursor/connection lifetime | Bounded pages or explicit scoped stream ownership |
| "Prepare for microservices" | Premature serialization and ceremony | Enforce ownership now; extract for measured need |
| "Mock all modules in tests" | Caller assumptions validate themselves | Real owner contract/persistence and grant tests |

## Finding Format

```text
Boundary: Billing owns invoice approval and billing.invoice
Failure: reconciliation job imports BillingRepository and updates status directly
Standard: A01:2025, ASVS V8/V15, CWE-653
Evidence: exact import and write path
Fix: actor-scoped BillingApi.approve plus DB role revocation
Why it holds: private package and database reject direct writes
Runtime cost: DTO mapping and one indexed tenant+invoice lookup
Residual gap: deployment grant still requires verification
```
