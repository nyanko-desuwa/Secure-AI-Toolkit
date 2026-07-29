# Domain-Driven Design Sources

Verified 2026-07-28. Use these for pattern definitions. Security conclusions in this skill
are mapped separately in [security-standards.md](security-standards.md); the generic DDD
sources do not claim that every context is automatically a secure trust boundary.

## Eric Evans - Domain-Driven Design

Eric Evans, *Domain-Driven Design: Tackling Complexity in the Heart of Software* (2003).

The source of the core vocabulary used here:

- Ubiquitous Language
- Bounded Context
- Context Map
- Entity
- Value Object
- Aggregate and Aggregate Root
- Repository
- Domain Event
- Anti-Corruption Layer

The central distinction this skill retains: a model is valid inside a bounded context. The
same word may carry another model elsewhere. Forcing one enterprise-wide model is generally
not feasible or cost-effective.

Use this source for terminology and strategic/tactical pattern intent, not for claims about a
specific ORM, event broker, database isolation mode, or runtime resource lifetime.

Reference:

- Evans classification and DDD index - <https://martinfowler.com/tags/domain%20driven%20design.html>

Verification note: Fowler's index identifies the name as coming from a 2003 book by Eric
Evans. Publisher/ISBN are deliberately omitted because they were not needed or verified for
this skill.

## Martin Fowler - Bounded Context

Martin Fowler, "Bounded Context", published 15 January 2014.

Verified definition: DDD divides a large model into bounded contexts, each with its own
internally consistent model, and makes relationships between contexts explicit through a
context map. Context boundaries usually follow breaks in language and team culture. A word
such as `Customer` or `Meter` can have distinct meanings in distinct contexts.

What this skill adds: the context is a trust boundary only when ownership is enforceable -
private tables/schema, a principal without grants outside the context, and a published
contract. Fowler's page defines the modelling boundary; it does not by itself prove database
or authorization isolation.

Reference:

- <https://martinfowler.com/bliki/BoundedContext.html>

Verified: 2026-07-28.

## Martin Fowler - DDD Aggregate

Martin Fowler, "DDD Aggregate", published 23 April 2013.

Verified definition: an aggregate is a cluster of domain objects treated as one unit. One
member is the aggregate root. Outside references point to the root, so it can guard the
integrity of the whole. Aggregates are the unit loaded and saved, and transactions should
not cross aggregate boundaries.

This is why this skill treats the root as the invariant enforcement point and the repository
as aggregate-in/aggregate-out. It also explains the runtime cost: if an aggregate is the unit
loaded and saved, drawing it too large loads and writes too much.

Reference:

- <https://martinfowler.com/bliki/DDD_Aggregate.html>

Verified: 2026-07-28.

## Vaughn Vernon - Effective Aggregate Design

Vaughn Vernon, "Effective Aggregate Design", posted 1 October 2011 as a three-part series.

The series covers:

- Part I - modelling an aggregate
- Part II - how aggregates relate to one another
- Part III - discovering and revising aggregate designs

This skill follows its practical emphasis: model true consistency constraints, keep
aggregates small, reference other aggregates by identity, and accept eventual consistency
between separate aggregates rather than pretending an in-memory check is atomic.

Reference page:

- <https://www.dddcommunity.org/library/vernon_2011/>

Verified: 2026-07-28.

## How These Sources Are Used

| Construct | Primary source here | Security/cost extension in this skill |
|---|---|---|
| Ubiquitous language | Evans | Naming discipline, explicitly not a security control |
| Bounded context and map | Evans, Fowler | Table ownership, DB role, contract, CWE-653/CWE-1220 |
| Aggregate/root | Evans, Fowler, Vernon | Consistency and authorization unit; load/write cost |
| Value object | Evans | Constructor validation and nominal ID types |
| Domain event | Evans | Minimal payload, consumer re-authorization, commit ordering |
| Repository | Evans | No lazy query escape; tenant scope inside the method |
| Anti-corruption layer | Evans | External-data trust boundary and strict validation |

## Claims Deliberately Not Made

- DDD does not require microservices. A modular monolith can enforce context ownership with
  modules, schemas, and DB roles.
- An aggregate does not guarantee authorization. It is the right enforcement point only if
  every write goes through the root and reads remain tenant/actor scoped.
- An event is not inherently reliable. Reliability depends on commit ordering, transport,
  retry, idempotency, and bounds.
- A bounded context does not imply a separate database. Separate schemas and principals can
  enforce a boundary in one database; separate databases can still have no boundary if both
  services share credentials.
- "One transaction per aggregate" is a design rule, not proof of any database isolation
  guarantee. Verify the actual transaction and isolation configuration.

## Related Runtime Sources

This file does not duplicate heap or queue guidance. For handler retention, long-lived unit
of work, N+1, and in-memory read-model growth, use:

- `skills/architecture/performance/`
- `skills/architecture/cqrs/`
- `skills/architecture/event-driven/`
