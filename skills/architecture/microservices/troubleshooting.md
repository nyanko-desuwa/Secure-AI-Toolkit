# Troubleshooting

## The split does not reduce coupling

Count synchronous calls, shared tables, shared packages, and coordinated releases. If most requests cross the seam and both sides deploy together, reverse the extraction into modules. Preserve interfaces and ownership tests inside a modular monolith. Distribution is not required for a boundary.

## Authorization is duplicated and inconsistent

Keep policy decision inputs explicit: subject, workload, action, object, tenant, and context. Put object loading and enforcement at the owner. Shared policy code may encode vocabulary, but each owner must provide current object facts. Add contract tests for deny cases. Do not centralize every decision in a remote policy service without a deadline and fail-closed behavior; that creates another hot dependency.

## mTLS works but callers can access the wrong objects

Expected. mTLS authenticates the workload channel. Inspect endpoint policy and object policy separately. Ensure the authenticated peer identity cannot be supplied as a header by the caller. Then load the object in the claimed tenant and evaluate the end-user action. Cite ASVS V12 for transport and V8 for authorization; do not conflate them.

## Service discovery causes unexpected outbound calls

Trace the destination from request field to logical name, registry response, DNS resolution, redirect, and socket. Replace arbitrary URL input with a finite dependency map. Validate each redirect and resolved address. Apply egress policy. Cloud metadata and private/control-plane destinations need explicit denial unless they are the named dependency. Source review cannot prove DNS rebinding or live egress rules; mark them unverified.

## Database connections fail after autoscaling

Calculate the upper bound across all replicas, workers, dependencies, migrations, and operators. Lower per-process pools, cap replicas, add a connection proxy where appropriate, and expose pool wait time. Avoid long transactions across remote calls. A smaller pool may raise queueing latency; measure it instead of hiding wait behind a larger pool.

## Retries amplify an outage

Disable retries for unsafe operations. Enforce an original request deadline, jitter, a small attempt cap, and a shared retry budget. Add a bulkhead per dependency and load shed before saturation. Watch attempt rate divided by original request rate. A ratio above one during dependency failure is amplification; set the alert from tested steady-state variance.

## Fan-out dominates tail latency

Inventory width and whether all results are required. Batch calls, cap concurrency, move optional work async, or return an explicit partial result. Do not retry every branch. Trace spans per request and dependency p95/p99 reveal the slow branch, but trace sampling can hide rare tails; keep aggregate dependency histograms too.

## Queue depth or saga state grows

Use oldest age as well as count. Stop admitting work when capacity is reached, scale only if the dependency can accept more load, and send permanent failures to a bounded DLQ. For sagas, expire minimal state and page an owner before expiry. Deleting state silently is not recovery. Retained payload bytes and sensitivity matter more than row count alone.

## Circuit-breaker metrics or caches consume memory

Search keys for raw URL, tenant, user, object, error text, or arbitrary label values. Replace with route templates and a finite dependency identifier. Cap entries, apply TTL/eviction, and export current key count. A breaker per legitimate tenant may still be unbounded. A cache hit rate does not show retained bytes or stale authorization; expose size and policy age.

## Distributed traces are too expensive

Bound spans per request, attribute length, exporter queue, and sampling. Never use object IDs, full URLs, tokens, or payloads as labels. Keep security-denial counters separate and low-cardinality. Sampling is a cost control, not proof that an event did not occur.

## Shared database cannot be removed immediately

Make the compromise visible. Assign one logical writer, revoke new cross-boundary writes, introduce owner views or stored contracts, and log remaining callers. Migrate reads, then writes, in bounded cohorts. Shared storage means the security boundary is not complete; do not claim otherwise.

## Migration diverges

Stop traffic at the predeclared divergence threshold. Preserve both records and reconciliation evidence. Route reads to the old authority until accepted new writes are reconciled. Fix forward or backfill in bounded batches. Do not erase the new store merely to make metrics green.

## Rollback is blocked by schema changes

Use expand/contract compatibility. Old and new readers must tolerate the transition before traffic moves. Rollback ends only when routing, accepted writes, queue events, and schema compatibility are accounted for. Test rollback in staging with writes during the switch.

## Observable limits to require

| Limit | Minimum evidence |
|---|---|
| End-to-end deadline | configured value and timeout count |
| Retry budget | attempts/original request and exhausted count |
| Pool | max, in-use, idle, waiters, wait duration |
| Fan-out | dependencies/request and concurrency |
| Queue | items/bytes, oldest age, ingress/egress, DLQ |
| Saga | active count, oldest age, bytes, expirations |
| Breaker/cache | finite key count, size, TTL/evictions |
| Tracing | spans/request, sample rate, drops, exporter queue |

If a value exists only in a live mesh, broker, database, or dashboard that is unavailable, report it as unverified. Do not infer runtime controls from a client library default.
