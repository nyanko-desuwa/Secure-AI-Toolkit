# Common Mistakes

Each mistake names the failure, why it happens, the structural fix, and why the fix holds.

## Modules Are Folders Around One Shared Data Model

Sales and Billing import the same ORM entities and write the same tables. A migration changes a
column's meaning and the non-owner still compiles. A tenant predicate can be skipped (`A01:2025`,
`CWE-653`, `CWE-1220`).

Fix: assign one owner per table, migration, and write role. Route other access through a contract;
revoke cross-schema grants. It holds because the database and compiler reject bypasses. Cost:
explicit queries/projections and migration work.

## Authorization Exists Only at HTTP

A controller checks a role, then calls `module.approve(id)`. A job or message handler calls the same
method without the check (`CWE-602`).

Fix: require `Actor` in the module API and authorize inside the owning use case. It holds because a
caller without actor scope cannot compile or execute the operation. Cost: actor construction and
validation per entry point.

## Generic Repository Is the Public Contract

`query(criteria)` or `IQueryable` lets every caller choose predicates, joins, and fields. Missing
tenant scope is absence, so review often misses it. Flexible strings can also become A05 injection.

Fix: intention-revealing, actor-scoped methods returning materialized DTOs. It holds because the
owner fixes query shape and output fields. Cost: more explicit methods and bounded mapping.

## Direct Cross-Module Table Reads "Only for Reporting"

The first read becomes a dependency on private column meaning and usually a later write. It also
runs with a role broader than either module needs.

Fix: owner-published projection, bounded query contract, or a reporting store populated from events.
It holds because consumers depend on a versioned meaning rather than private storage. Cost: staleness,
outbox work, or an extra call.

## One Transaction Spans Module Calls

Module A opens a transaction, calls B, and waits while retaining a connection and locks. B may call
back or acquire locks in another order. Timeouts and exceptions make cleanup fragile (`CWE-772`).

Fix: call before the transaction, keep one owner per transaction, or model a pending state and
compensation. It holds because no foreign work runs while local locks are held. Cost: staleness or
eventual consistency must be designed.

## Event Published Before Commit or Only After Commit

Before commit, consumers can act on rolled-back state. Only after commit, a crash loses the event.

Fix: write an outbox row with state, then publish committed rows. It holds because intent and state
are atomic. Cost: at-least-once delivery, duplicate handling, polling, lag, and retention.

## Event Is Treated as Authorization

A payment handler trusts `InvoiceApproved` as permission to disburse. Any buggy publisher or replay
can trigger the consequence (`A01:2025`).

Fix: validate the event and re-check authoritative local state and policy. It holds because the
consequence owner decides. Cost: one local lookup and idempotency record.

## Global Bus Registers Scoped Handlers

A request creates a handler that subscribes to a singleton bus and never unsubscribes. Listeners,
actor state, and repositories accumulate; one event runs every old handler (`CWE-770`, `CWE-772`).

Fix: register stateless host handlers once, or return and invoke a disposer from the owning scope. It
holds because lifetime ownership is explicit. Cost: per-event scoped dependency resolution.

## Singleton Module Remembers Current Tenant

An instance field stores the last actor, tenant, transaction, or result. Concurrent calls race and
later requests receive stale cross-tenant state (`A01:2025`).

Fix: pass request state through parameters and keep scoped services scoped. Shared caches require
identity in the key, an entry/byte limit, and TTL. Cost: parameters and bounded-cache misses.

## In-Process Queue or Cache Has No Bound

A bare queue or map grows with input (`CWE-770`). Restarting merely resets the attack.

Fix: maximum depth/bytes/entries, saturation behavior, TTL/eviction, and metrics. It holds because
memory is no longer a function of traffic without a ceiling. Cost: rejection, blocking, or eviction.

## Lazy Data Escapes the Owner

A module returns a generator, stream, cursor, lazy relation, or ORM query. The caller can keep a
handle open, observe a disposed context, or append an unsafe predicate (`CWE-772`).

Fix: materialize a bounded page inside the module or expose a clearly scoped callback. It holds
because acquisition and release share one owner. Cost: page allocation; enforce a limit.

## Contract Tests Mock the Owning Module

Mocks confirm the caller's assumptions, not the owner's authorization, SQL, grants, or serialization.

Fix: run module API tests against the real adapter and database role; add compile-time import tests.
It holds because it exercises the enforcement point. Cost: slower CI and test schema lifecycle.

## Modular Monolith Used as a Microservice Waiting Room

Teams add events and interfaces to every class without a real ownership split. Navigation and
allocation rise while shared tables remain.

Fix: add boundaries only for capabilities with distinct rules/data ownership. Extract a service only
for measured independent scaling, deployment, isolation, or technology need. Cost is then paid for a
stated benefit, not fashion.
