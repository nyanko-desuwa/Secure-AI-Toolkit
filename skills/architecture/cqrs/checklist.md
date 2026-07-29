# CQRS Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable" needs
a one-line reason - an unexplained skip reads the same as an oversight.

Only run the sections the change touches. A change at level 1 does not need the projector or
event store sections.

## Is the split justified at all

- [ ] The read shape genuinely differs from the write shape, and you can say how
- [ ] The read/write asymmetry is measured, not assumed, if going past level 1
- [ ] Level chosen explicitly (0 to 4) and written down, not arrived at by accident
- [ ] A read replica plus tuned queries was considered and rejected for a stated reason
- [ ] The split is scoped to one bounded context, not applied across the whole system
- [ ] No new broker, projector, or second store added for a CRUD screen

## Command side

- [ ] Command is named after a business intent, not a table operation
- [ ] Command returns an identifier or an acknowledgement, not the whole entity
- [ ] Payload schema is closed - unknown keys rejected, no free-form field map
- [ ] Actor and tenant come from the session, never from the request body
- [ ] The rule that governs the change lives in the aggregate, not in the handler
- [ ] Every state change path passes through that rule; no direct table update bypasses it
- [ ] Command carries a command ID, and the ID is deduplicated
- [ ] Dedup claim and state change commit in the same transaction, not check-then-act
- [ ] Dedup table has a retention policy and an index on the retention column
- [ ] Failure returns a distinguishable result: rejected by rule vs. not found vs. duplicate

## Projection schema

- [ ] Tenant ID is a column on every projection that holds tenant-scoped data
- [ ] Tenant ID is part of the primary key, so a projector that forgets it collides
- [ ] Owner ID is present even if no current screen displays it
- [ ] Every index the queries use is prefixed by the tenant column
- [ ] Row-level security enabled where the database supports it, with `FORCE` on
- [ ] Columns are the ones the screen needs; no `SELECT *` built the projection
- [ ] No internal field projected: no password hash, MFA secret, fraud score, internal note
- [ ] A new column on a source table cannot appear in a response without a code change
- [ ] Projection is versioned in its name, so a rebuild can swap rather than truncate

## Query side

- [ ] Repository or reader interface has no method that omits the tenant
- [ ] Tenant is a required parameter, so an unscoped call does not compile
- [ ] Page size is clamped server-side, with a stated maximum
- [ ] Response type is declared explicitly; no ORM entity or raw row is serialized
- [ ] Missing row and another tenant's row return the same result to the caller
- [ ] No query writes. No lazy upsert, no "create if missing", no counter increment
- [ ] Deep pagination uses keyset, not a large `OFFSET`

## Consistency

- [ ] No authorization decision reads from an eventually consistent projection
- [ ] No check-then-act where the check reads a projection and the act writes elsewhere
- [ ] Uniqueness, balance, and quota invariants are enforced in the authoritative store
- [ ] Read-your-own-write handled deliberately: optimistic render, read-write routing, or
      version polling - not by making the projector synchronous
- [ ] Projection lag is emitted as a metric and has an alert threshold
- [ ] The staleness window is written down somewhere a product owner has seen

## Projector lifetime and cost

- [ ] Nothing accumulates per entity in memory. The database holds running state
- [ ] Any in-memory cache has a max size and a TTL, with the number's basis stated
- [ ] Correctness does not depend on that cache being warm or present
- [ ] Every projector handler is idempotent - a sequence or version guard rejects replays
- [ ] Handler is a pure function of the event plus current projection state
- [ ] Projector has no side effects: no email, no webhook, no third-party call
- [ ] Queue or channel between command side and projector is bounded
- [ ] Full behaviour chosen and documented: block, drop, or reject
- [ ] Poison-message path exists: a failing event goes to a dead letter, not an infinite retry
- [ ] Projector failure does not fail the command that produced the event
- [ ] Replay cost estimated as rows x per-row cost, with the number stated
- [ ] Rebuild builds into a new table and swaps; it does not truncate the live projection
- [ ] Replay is throttled so it cannot saturate the store during production traffic

## Dual writes

- [ ] No database commit followed by a separate broker publish
- [ ] Event is written as a row in the same transaction as the state change
- [ ] Relay claims rows without two workers taking the same batch (`SKIP LOCKED` or equivalent)
- [ ] Outbox rows are deleted or archived on a schedule, with an index on the publish column
- [ ] Ordering guarantee stated: global with a throughput ceiling, or per-aggregate
- [ ] At-least-once is stated as the guarantee. Nothing claims exactly-once

## Event store (only if event sourcing)

- [ ] Event sourcing was a separate, justified decision, not a consequence of choosing CQRS
- [ ] Event handlers have no clock, random, or network access
- [ ] Events store what was decided, including the rate or price applied, not a lookup key
- [ ] Snapshots are reproducible from events and versioned with the handler code
- [ ] Only additive schema changes made; no field renamed or repurposed
- [ ] New shapes are new event types with an upcaster, and the upcaster is kept
- [ ] Serialization uses an explicit contract, not reflection over class names
- [ ] Personal data in events is encrypted per subject, with the key held outside the store
- [ ] Erasure path exists and has been executed end to end at least once in a test
- [ ] Replay tolerates an undecryptable payload without throwing
- [ ] Erasure also rebuilds or purges projections that hold plaintext
- [ ] Backup retention window for the key store is known and stated
- [ ] Legal review obtained for whatever erasure approach was chosen

## Before returning

- [ ] Build or compile step run
- [ ] Relevant tests run, output reported honestly
- [ ] A test asserts that a cross-tenant read returns nothing, not just that the happy path works
- [ ] A test delivers the same event twice and asserts the projection is unchanged
- [ ] Anything depending on runtime state - lag, RLS enabled, projector running - labelled
      as unverified from source
- [ ] Any recommendation to split stated with its cost, not just its benefit
