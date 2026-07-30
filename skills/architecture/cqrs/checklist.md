# CQRS Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable" needs
a one-line reason - an unexplained skip reads the same as an oversight.

Only run the sections the change touches. A change at level 1 does not need the projector or
event store sections.

## Is the split justified at all

- [ ] [recommended] The read shape genuinely differs from the write shape, and you can say how
- [ ] [recommended] The read/write asymmetry is measured, not assumed, if going past level 1
- [ ] [recommended] Level chosen explicitly (0 to 4) and written down, not arrived at by accident
- [ ] [recommended] A read replica plus tuned queries was considered and rejected for a stated reason
- [ ] [recommended] The split is scoped to one bounded context, not applied across the whole system
- [ ] [optional] No new broker, projector, or second store added for a CRUD screen

## Command side

- [ ] [recommended] Command is named after a business intent, not a table operation
- [ ] [optional] Command returns an identifier or an acknowledgement, not the whole entity
- [ ] [critical] Payload schema is closed - unknown keys rejected, no free-form field map
- [ ] [critical] Actor and tenant come from the session, never from the request body
- [ ] [recommended] The rule that governs the change lives in the aggregate, not in the handler
- [ ] [critical] Every state change path passes through that rule; no direct table update bypasses it
- [ ] [recommended] Command carries a command ID, and the ID is deduplicated
- [ ] [recommended] Dedup claim and state change commit in the same transaction, not check-then-act
- [ ] [recommended] Dedup table has a retention policy and an index on the retention column
- [ ] [optional] Failure returns a distinguishable result: rejected by rule vs. not found vs. duplicate

## Projection schema

- [ ] [critical] Tenant ID is a column on every projection that holds tenant-scoped data
- [ ] [critical] Tenant ID is part of the primary key, so a projector that forgets it collides
- [ ] [recommended] Owner ID is present even if no current screen displays it
- [ ] [recommended] Every index the queries use is prefixed by the tenant column
- [ ] [recommended] Row-level security enabled where the database supports it, with `FORCE` on
- [ ] [recommended] Columns are the ones the screen needs; no `SELECT *` built the projection
- [ ] [critical] No internal field projected: no password hash, MFA secret, fraud score, internal note
- [ ] [recommended] A new column on a source table cannot appear in a response without a code change
- [ ] [optional] Projection is versioned in its name, so a rebuild can swap rather than truncate

## Query side

- [ ] [critical] Repository or reader interface has no method that omits the tenant
- [ ] [critical] Tenant is a required parameter, so an unscoped call does not compile
- [ ] [recommended] Page size is clamped server-side, with a stated maximum
- [ ] [recommended] Response type is declared explicitly; no ORM entity or raw row is serialized
- [ ] [recommended] Missing row and another tenant's row return the same result to the caller
- [ ] [recommended] No query writes. No lazy upsert, no "create if missing", no counter increment
- [ ] [optional] Deep pagination uses keyset, not a large `OFFSET`

## Consistency

- [ ] [critical] No authorization decision reads from an eventually consistent projection
- [ ] [recommended] No check-then-act where the check reads a projection and the act writes elsewhere
- [ ] [critical] Uniqueness, balance, and quota invariants are enforced in the authoritative store
- [ ] [optional] Read-your-own-write handled deliberately: optimistic render, read-write routing, or
      version polling - not by making the projector synchronous
- [ ] [recommended] Projection lag is emitted as a metric and has an alert threshold
- [ ] [optional] The staleness window is written down somewhere a product owner has seen

## Projector lifetime and cost

- [ ] [recommended] Nothing accumulates per entity in memory. The database holds running state
- [ ] [recommended] Any in-memory cache has a max size and a TTL, with the number's basis stated
- [ ] [recommended] Correctness does not depend on that cache being warm or present
- [ ] [recommended] Every projector handler is idempotent - a sequence or version guard rejects replays
- [ ] [recommended] Handler is a pure function of the event plus current projection state
- [ ] [recommended] Projector has no side effects: no email, no webhook, no third-party call
- [ ] [recommended] Queue or channel between command side and projector is bounded
- [ ] [recommended] Full behaviour chosen and documented: block, drop, or reject
- [ ] [recommended] Poison-message path exists: a failing event goes to a dead letter, not an infinite retry
- [ ] [recommended] Projector failure does not fail the command that produced the event
- [ ] [optional] Replay cost estimated as rows x per-row cost, with the number stated
- [ ] [recommended] Rebuild builds into a new table and swaps; it does not truncate the live projection
- [ ] [recommended] Replay is throttled so it cannot saturate the store during production traffic

## Dual writes

- [ ] [recommended] No database commit followed by a separate broker publish
- [ ] [recommended] Event is written as a row in the same transaction as the state change
- [ ] [recommended] Relay claims rows without two workers taking the same batch (`SKIP LOCKED` or equivalent)
- [ ] [recommended] Outbox rows are deleted or archived on a schedule, with an index on the publish column
- [ ] [recommended] Ordering guarantee stated: global with a throughput ceiling, or per-aggregate
- [ ] [recommended] At-least-once is stated as the guarantee. Nothing claims exactly-once

## Event store (only if event sourcing)

- [ ] [optional] Event sourcing was a separate, justified decision, not a consequence of choosing CQRS
- [ ] [recommended] Event handlers have no clock, random, or network access
- [ ] [recommended] Events store what was decided, including the rate or price applied, not a lookup key
- [ ] [recommended] Snapshots are reproducible from events and versioned with the handler code
- [ ] [recommended] Only additive schema changes made; no field renamed or repurposed
- [ ] [recommended] New shapes are new event types with an upcaster, and the upcaster is kept
- [ ] [critical] Serialization uses an explicit contract, not reflection over class names
- [ ] [critical] Personal data in events is encrypted per subject, with the key held outside the store
- [ ] [recommended] Erasure path exists and has been executed end to end at least once in a test
- [ ] [recommended] Replay tolerates an undecryptable payload without throwing
- [ ] [recommended] Erasure also rebuilds or purges projections that hold plaintext
- [ ] [optional] Backup retention window for the key store is known and stated
- [ ] [optional] Legal review obtained for whatever erasure approach was chosen

## Before returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Relevant tests run, output reported honestly
- [ ] [recommended] A test asserts that a cross-tenant read returns nothing, not just that the happy path works
- [ ] [recommended] A test delivers the same event twice and asserts the projection is unchanged
- [ ] [critical] Anything depending on runtime state - lag, RLS enabled, projector running - labelled
      as unverified from source
- [ ] [recommended] Any recommendation to split stated with its cost, not just its benefit
