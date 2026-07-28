# DDD Checklist

Mark each item pass, fail, or not applicable. A not-applicable item needs a reason. An
unchecked control is either a fix or an owned residual risk.

## Bounded Contexts and Trust

- [ ] Each context has a written list of tables it owns
- [ ] No two contexts write the same table
- [ ] Each context uses a DB role with no grant on another context's private schema
- [ ] Cross-context reads use a versioned contract, not a direct table query
- [ ] The contract exposes only fields the consumer needs
- [ ] Context map names the direction, protocol, and data trust at every relationship
- [ ] External and legacy data is parsed and validated in an anti-corruption layer
- [ ] Tenant identity comes from the authenticated caller, not an external payload

## Aggregates and Authorization

- [ ] Every aggregate has a named invariant that justifies its boundary
- [ ] The aggregate root is the only public mutation entry point
- [ ] Child collections cannot be appended to or replaced by outside code
- [ ] Every read, write, and delete is scoped by the actor or tenant at the repository boundary
- [ ] Every write path has been enumerated: API, job, import, admin, migration, and raw SQL
- [ ] Other aggregates are referenced by ID, not held as mutable object graphs
- [ ] A consumer does not treat a domain event as proof of authorization
- [ ] A cross-aggregate invariant has a transaction/constraint design, not only an in-memory check
- [ ] Eventual consistency windows have a defined reader behaviour and compensating action

## Value Objects

- [ ] IDs with different security meanings have different types (`TenantId`, `UserId`, `OrderId`)
- [ ] Email, money, and tenant values validate at construction
- [ ] Invalid values cannot be created through public constructors or setters
- [ ] Currency and amount arithmetic cannot silently mix currencies or overflow chosen bounds
- [ ] Boundary parsing produces domain types before business logic runs
- [ ] Runtime validation still exists for values crossing a process or language boundary

## Repositories and Persistence

- [ ] A repository exists per aggregate root, not as a generic table/query escape hatch
- [ ] Repository methods return materialised aggregates or explicit read DTOs
- [ ] No repository method returns `IQueryable`, a lazy ORM query, or a mutable persistence row
- [ ] Every list method has a maximum page/batch size
- [ ] Tenant/actor scoping is in the repository query, not a caller's follow-up `if`
- [ ] The unit of work is scoped and disposed; it is not a process singleton
- [ ] Generated SQL has been checked for N+1 loading and row multiplication

## Events and Delivery

- [ ] Domain events contain a minimal, explicit, immutable contract
- [ ] Events do not carry full entities, secrets, internal notes, or unneeded PII
- [ ] The event is recorded with the state change, then published after commit
- [ ] An outbox or equivalent closes the state/publish crash window where required
- [ ] Consumers authenticate and authorize their own consequential action
- [ ] Consumers are idempotent for at-least-once delivery
- [ ] In-process dispatch has a bounded handler count, timeout, and cancellation policy
- [ ] Slow or I/O-heavy handlers run outside the publishing transaction

## Resource Lifecycle and Cost

- [ ] Every event subscription has a disposer and a named owner
- [ ] Per-request handlers are not registered on application-lifetime buses
- [ ] Handler closures do not retain request-scoped services after the request
- [ ] Unit-of-work, DB context, cursor, and connection release on success, error, and cancellation
- [ ] In-memory read models have a maximum size, TTL, or eviction policy
- [ ] Aggregate load size and write row count were measured for the hot operations
- [ ] N+1 and retained-entity growth were checked under a realistic collection size
- [ ] Backpressure or a queue bound exists where event handlers can outpace producers
- [ ] Details and heap diagnosis are handed to `skills/architecture/performance/`

## Scope Decision

- [ ] The domain has a real invariant or language/context split that pays for DDD's cost
- [ ] If this is CRUD with no invariant, a validated request plus scoped query was chosen instead
- [ ] The design says what happens when the domain expert, legacy schema, or contract is unavailable
- [ ] The relevant residual gaps are named; no ASVS level is claimed without verification
