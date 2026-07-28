# Troubleshooting

## The Existing Database Has Shared Tables

Do not claim isolation. Inventory all readers, writers, migrations, triggers, jobs, and database
roles. Name one owner, route non-owner writes through its contract, add a compatibility projection
for reads, then revoke grants. Move writes first because they bypass invariants. During migration,
record the shared table as a residual `CWE-653` risk.

Cost: dual paths, backfill/reconciliation, and temporary query overhead. Avoid a flag-day split unless
the exposure demands it.

## A Cross-Module Operation Must Be Atomic

Write the invariant in one sentence. If correctness requires both states to commit together, they
may be one module boundary. Do not split an invariant to satisfy a diagram.

Otherwise model explicit states such as `PendingReservation -> Accepted | Rejected`, with an
idempotent command, timeout, retry budget, compensation, reader behavior, and operator recovery.
Cost: the system is briefly incomplete and needs durable workflow state. If the business cannot
accept that, keep the local transaction and boundary together.

## Contract Calls Cause N+1 Queries

Count calls and generated SQL. For a bounded list, add an owner-provided batch query or projection.
Do not expose a repository or let the caller join private tables. A read store may trade immediate
consistency for one query; document staleness and test tenant scoping.

## The Module API Has Too Many Methods

Group by actor intent, not tables. Separate commands from bounded query projections. If methods are
only CRUD and all share one ownership predicate, the module may not earn its ceremony; collapse to a
smaller scoped component.

## Package Rules Cannot Prevent Imports

Use separate build projects, package export maps, Java package/module visibility, or an import
linter. Add a CI test that scans forbidden module-to-infrastructure dependencies and table names.
Where language enforcement is weak, database roles remain the last boundary.

## The Framework Shares One ORM Context

A process or request-wide context lets modules see each other's tracked entities and can retain a
large graph. Give each module a scoped unit of work/repository and prevent public ORM types. If the
framework mandates one context, constrain access through private sets/adapters and grants; state
that compiler isolation is weaker. Measure tracked entity count and connection duration.

## Outbox Lag Grows

Check producer rate, batch size, publish concurrency, dependency latency, poison messages, and lock
contention. Bound concurrency; do not increase it beyond connection or broker capacity. Move poison
messages to a visible failed state after a bounded retry budget. Alert on oldest undispatched age,
not only row count. Delete/archive dispatched rows under a retention policy.

## Handlers Run Twice

At-least-once delivery makes duplicates normal. Persist an idempotency key with the local effect in
one transaction. A check-then-act in memory races. If listener count grows with uptime, also inspect
global bus registration; duplicate listeners are a separate `CWE-772` lifetime defect.

## Listeners or Memory Grow with Uptime

Inventory every `on`, `subscribe`, timer, task, queue, and cache. Name owner and release point. Host
handlers register once; scoped subscriptions keep and call disposers on all exits. Remove captured
actor/tenant/repository objects. Compare heap snapshots under steady load; source alone cannot prove
the retainer. Use `skills/architecture/performance/` for diagnosis.

## A Singleton Needs Tenant Data

It does not. Pass actor/tenant per call or resolve a scoped dependency per message. A shared cache
can hold tenant-derived values only when tenant is part of the key and size/age are bounded. If
permissions can change, cache authorization decisions no longer than their documented freshness
budget.

## A Lazy Iterator Is Needed for Large Results

Do not return a cursor-backed iterator across a module boundary. Prefer keyset-paginated calls. If
streaming is required, expose a scope-owned callback or async resource whose cancellation and close
semantics are explicit, and test early termination. Bound bytes/records and total duration.

## Module Contract Tests Are Slow

Keep pure domain tests fast, but retain a focused database-backed contract suite for tenant scope,
grants, serialization, rollback/outbox atomicity, and duplicates. Reuse infrastructure only between
tests when state is reset and no actor/transaction leaks. Mock external transports after testing the
outbox record, not the owning repository.

## When to Extract a Microservice

Require evidence: independent scaling profile, deployment cadence, regulatory/process isolation,
failure containment, or a runtime/technology constraint. Then confirm the module already has owned
data, narrow contracts, idempotency, timeouts, and observability. Extraction adds serialization,
network failure, retries, version compatibility, more pools, and operational ownership.

Do not extract to solve cyclic dependencies or shared tables. Fix those inside the monolith first;
otherwise the result is a distributed monolith with weaker transactions and higher latency.

## When NOT to Use a Modular Monolith

Use a thin tenant-scoped handler for simple CRUD with no cross-entry invariant. Use a bounded direct
projection for read-only reports. Use one module when an invariant genuinely spans the proposed
split. Use a short script for one-off transformations. Choose independently deployed services only
when their isolation benefit is measured and staffed. Ceremony makes authorization harder to find;
that is a security regression, not harmless overengineering.
