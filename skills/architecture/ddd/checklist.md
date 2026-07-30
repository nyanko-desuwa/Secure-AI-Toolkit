# DDD Checklist

Mark each item pass, fail, or not applicable. A not-applicable item needs a reason. An
unchecked control is either a fix or an owned residual risk.

## Bounded Contexts and Trust

- [ ] [recommended] Each context has a written list of tables it owns
- [ ] [critical] No two contexts write the same table
- [ ] [critical] Each context uses a DB role with no grant on another context's private schema
- [ ] [recommended] Cross-context reads use a versioned contract, not a direct table query
- [ ] [recommended] The contract exposes only fields the consumer needs
- [ ] [recommended] Context map names the direction, protocol, and data trust at every relationship
- [ ] [critical] External and legacy data is parsed and validated in an anti-corruption layer
- [ ] [critical] Tenant identity comes from the authenticated caller, not an external payload

## Aggregates and Authorization

- [ ] [recommended] Every aggregate has a named invariant that justifies its boundary
- [ ] [recommended] The aggregate root is the only public mutation entry point
- [ ] [recommended] Child collections cannot be appended to or replaced by outside code
- [ ] [critical] Every read, write, and delete is scoped by the actor or tenant at the repository boundary
- [ ] [critical] Every write path has been enumerated: API, job, import, admin, migration, and raw SQL
- [ ] [recommended] Other aggregates are referenced by ID, not held as mutable object graphs
- [ ] [critical] A consumer does not treat a domain event as proof of authorization
- [ ] [recommended] A cross-aggregate invariant has a transaction/constraint design, not only an in-memory check
- [ ] [recommended] Eventual consistency windows have a defined reader behaviour and compensating action

## Value Objects

- [ ] [recommended] IDs with different security meanings have different types (`TenantId`, `UserId`, `OrderId`)
- [ ] [recommended] Email, money, and tenant values validate at construction
- [ ] [recommended] Invalid values cannot be created through public constructors or setters
- [ ] [recommended] Currency and amount arithmetic cannot silently mix currencies or overflow chosen bounds
- [ ] [recommended] Boundary parsing produces domain types before business logic runs
- [ ] [recommended] Runtime validation still exists for values crossing a process or language boundary

## Repositories and Persistence

- [ ] [recommended] A repository exists per aggregate root, not as a generic table/query escape hatch
- [ ] [recommended] Repository methods return materialised aggregates or explicit read DTOs
- [ ] [recommended] No repository method returns `IQueryable`, a lazy ORM query, or a mutable persistence row
- [ ] [recommended] Every list method has a maximum page/batch size
- [ ] [critical] Tenant/actor scoping is in the repository query, not a caller's follow-up `if`
- [ ] [recommended] The unit of work is scoped and disposed; it is not a process singleton
- [ ] [recommended] Generated SQL has been checked for N+1 loading and row multiplication

## Events and Delivery

- [ ] [recommended] Domain events contain a minimal, explicit, immutable contract
- [ ] [critical] Events do not carry full entities, secrets, internal notes, or unneeded PII
- [ ] [recommended] The event is recorded with the state change, then published after commit
- [ ] [recommended] An outbox or equivalent closes the state/publish crash window where required
- [ ] [critical] Consumers authenticate and authorize their own consequential action
- [ ] [recommended] Consumers are idempotent for at-least-once delivery
- [ ] [recommended] In-process dispatch has a bounded handler count, timeout, and cancellation policy
- [ ] [recommended] Slow or I/O-heavy handlers run outside the publishing transaction

## Resource Lifecycle and Cost

- [ ] [recommended] Every event subscription has a disposer and a named owner
- [ ] [recommended] Per-request handlers are not registered on application-lifetime buses
- [ ] [recommended] Handler closures do not retain request-scoped services after the request
- [ ] [recommended] Unit-of-work, DB context, cursor, and connection release on success, error, and cancellation
- [ ] [recommended] In-memory read models have a maximum size, TTL, or eviction policy
- [ ] [recommended] Aggregate load size and write row count were measured for the hot operations
- [ ] [recommended] N+1 and retained-entity growth were checked under a realistic collection size
- [ ] [recommended] Backpressure or a queue bound exists where event handlers can outpace producers
- [ ] [optional] Details and heap diagnosis are handed to `skills/architecture/performance/`

## Scope Decision

- [ ] [optional] The domain has a real invariant or language/context split that pays for DDD's cost
- [ ] [optional] If this is CRUD with no invariant, a validated request plus scoped query was chosen instead
- [ ] [recommended] The design says what happens when the domain expert, legacy schema, or contract is unavailable
- [ ] [critical] The relevant residual gaps are named; no ASVS level is claimed without verification
