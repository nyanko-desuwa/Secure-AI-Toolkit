# Checklist

Mark every item pass, fail, or not applicable with one line of evidence. An unchecked item is a
change or an owned residual risk.

## Module ownership

- [ ] [recommended] Each module has a named business capability and owner.
- [ ] [recommended] Each module lists the tables/schema it owns and the migrations that change them.
- [ ] [recommended] No two modules write the same table.
- [ ] [critical] Each module database role has no write grant to another module's private schema.
- [ ] [recommended] Cross-module reads use a versioned contract or explicit projection, never a direct table/ORM query.
- [ ] [recommended] Private implementation packages are not importable from other modules.
- [ ] [recommended] Dependency direction points to public contracts/domain, not concrete infrastructure.

## Actor-scoped contracts

- [ ] [critical] Every command, query, and consequential event handler receives an explicit actor or system principal.
- [ ] [critical] Tenant/resource scope is required by the contract and applied in the owner's query.
- [ ] [critical] Authorization is in the owning use case, not only a controller, client, or event producer.
- [ ] [critical] Input DTOs reject unknown fields, bound collections/strings, and prevent mass assignment.
- [ ] [critical] Output DTOs are allowlists and contain no ORM entities, cursors, secrets, or unrelated tenant IDs.
- [ ] [recommended] Actor, tenant, and resource IDs have distinct types where the language permits.

## Transactions and events

- [ ] [recommended] A transaction writes only the owning module's state and its outbox rows.
- [ ] [recommended] No transaction is held while calling another module, network service, or slow handler.
- [ ] [recommended] Outbox rows have a stable idempotency/message key, type/version, tenant scope, and retention policy.
- [ ] [recommended] Publishing happens after commit and duplicate delivery is expected and handled.
- [ ] [critical] Consumers validate payloads and re-authorize consequential actions against authoritative local state.
- [ ] [recommended] Retry count, timeout, queue depth, and saturation behaviour are bounded and observable.

## Lifecycle and runtime cost

- [ ] [recommended] Global bus subscriptions are registered once or have an owner and disposer.
- [ ] [recommended] Request/tenant/actor state is not retained by a singleton or module-level mutable state.
- [ ] [recommended] In-process queues, caches, batches, and fan-out have explicit limits and eviction/TTL where needed.
- [ ] [recommended] Connections, cursors, locks, timers, tasks, and streams release on success, error, cancellation, and shutdown.
- [ ] [recommended] Lazy iterators do not cross module boundaries or hide open handles; results are materialized or scoped.
- [ ] [recommended] Query count, rows/bytes loaded, allocation, lock time, queue depth, and retained references were measured.
- [ ] [recommended] Metrics and alerts identify module, tenant-safe operation, rejection, lag, and cleanup failures.

## Contract verification

- [ ] [critical] Contract tests cover allowed and denied actors, wrong tenant, missing fields, limits, and output fields.
- [ ] [critical] Persistence tests prove a module cannot access another schema with its runtime role.
- [ ] [recommended] Architecture tests reject forbidden imports and direct table names outside owners.
- [ ] [recommended] Outbox tests cover rollback, duplicate delivery, poison messages, retry exhaustion, and replay.
- [ ] [recommended] Tests run from HTTP, job, and message entry points so no adapter-only check survives.

## Scope decision

- [ ] [optional] The feature has a real invariant, ownership boundary, or multiple entry points that pays for this structure.
- [ ] [optional] If it is simple CRUD or a report, the smaller scoped-query/projection design was considered.
- [ ] [optional] The design documents when a microservice would earn its operational cost.
- [ ] [recommended] Residual shared-table, grant, runtime, or delivery gaps have an owner and removal condition.
