# Clean Architecture Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. A not-applicable answer
needs one sentence; silence is indistinguishable from an oversight.

## Dependency Direction

- [ ] [recommended] Domain and application code import no web framework, ORM, serializer, or DI container
- [ ] [recommended] Source dependencies point inward; infrastructure implements interfaces owned by inner layers
- [ ] [recommended] Project references or import-linter rules enforce the direction, rather than folder names alone
- [ ] [recommended] Repository interfaces use domain types, not ORM rows or framework query types
- [ ] [recommended] No `IQueryable`, lazy relation, ORM session, or query builder crosses an inner-layer boundary
- [ ] [recommended] Any framework exception is translated before it reaches the domain

## Actor and Authorization (`A01:2025` · ASVS V8)

- [ ] [critical] Every security-relevant use case takes an explicit, non-optional actor parameter
- [ ] [critical] Actor identity and tenant derive from a verified credential, never a request body or header
- [ ] [critical] The use case decides permission for the intent; controller guards are defence in depth
- [ ] [critical] Every read, write, and delete is scoped to the actor's tenant or ownership
- [ ] [critical] Background jobs, CLI commands, message handlers, and tests provide a named principal
- [ ] [recommended] System actors are restricted, greppable, and included in the audit trail
- [ ] [critical] Authorization failure denies; dependency failure never grants access
- [ ] [recommended] Missing and not-owned objects have an indistinguishable response where existence is sensitive

## Entities and Validation (`A05`, `A06` · ASVS V2)

- [ ] [critical] Edge schemas validate format, type, range, length, and reject unknown fields
- [ ] [recommended] Domain constructors or factories enforce business invariants
- [ ] [recommended] Invalid entities cannot be constructed through a public constructor or mutable setter
- [ ] [recommended] Every alternate entry point uses the same entity factory
- [ ] [recommended] Rehydration is a named, restricted path and does not become a general invariant bypass
- [ ] [recommended] Domain operations prevent invalid transitions, not only invalid initial state

## Ports and Repositories

- [ ] [recommended] Each port is defined in the layer that calls it
- [ ] [critical] Repository methods reveal intent and include tenant/ownership where needed
- [ ] [recommended] Results are materialized inside the adapter; lazy loading does not cross the boundary
- [ ] [recommended] Repository per aggregate has not created an unmeasured 1+N query path
- [ ] [recommended] Query count is asserted in a test where N+1 is plausible
- [ ] [recommended] List methods have a server-side maximum and stable pagination
- [ ] [optional] Read-only projections skip aggregate construction when invariants are not needed
- [ ] [recommended] Database row-level isolation is considered where one omitted predicate has severe impact

## Input and Output DTOs (`API3:2023`)

- [ ] [critical] Input commands explicitly list writable fields and reject unknown keys (`CWE-915`)
- [ ] [critical] Output DTOs explicitly list readable fields; no entity or ORM model reaches the serializer
- [ ] [critical] No object spread, reflection convention, or automatic mapper silently copies new fields
- [ ] [critical] Field-level authorization happens while building the DTO, with the actor available
- [ ] [recommended] Exact response keys are asserted in a test for sensitive resources
- [ ] [critical] DTOs exclude password hashes, reset tokens, internal flags, risk scores, and unrelated tenant IDs

## DI and Resource Lifetime (`A01`, `A06`)

- [ ] [recommended] Use cases, repositories, ORM contexts, actor context, and tenant context are scoped per unit of work
- [ ] [critical] No singleton captures a scoped user, tenant, request, ORM context, cursor, or connection
- [ ] [recommended] Singleton use cases have no instance-field lookup cache
- [ ] [critical] Long-lived caches include tenant in the key where values are tenant-specific
- [ ] [recommended] Every cache has a maximum size and TTL or an explicit reason for no TTL
- [ ] [recommended] Scope validation or the container's equivalent runs in CI
- [ ] [recommended] A singleton worker creates and disposes one scope per job/message
- [ ] [recommended] The container disposes what it creates; manually created resources have `using`, `with`, or `finally`
- [ ] [recommended] No resource lifetime is longer than the unit of work that owns it
- [ ] [optional] Heap-level concerns are handed to `skills/architecture/performance/`, not hand-waved here

## Cancellation and Outbound Ports (`API4:2023`)

- [ ] [recommended] Every I/O port method accepts the runtime's cancellation/deadline primitive
- [ ] [recommended] Cancellation propagates from entry point through use case and port without becoming a field
- [ ] [recommended] Each adapter sets a dependency-specific timeout linked to the caller's deadline
- [ ] [recommended] Response and request sizes are bounded on bytes actually read or sent
- [ ] [recommended] Retries have an attempt cap, total budget, jitter, and idempotency rules
- [ ] [critical] Cancellation and timeout failures do not leave a partial write or fail authorization open

## Cost and Fit

- [ ] [optional] Mapping allocations per response are acknowledged; hot list paths project directly to DTOs
- [ ] [recommended] Query count per request is known for aggregate list paths
- [ ] [recommended] ORM change tracking does not retain an unbounded result set until request end
- [ ] [optional] Every one-implementation interface has a reason: boundary enforcement, replacement, or compilation
- [ ] [optional] A thin controller plus scoped query was considered for CRUD with no domain rules
- [ ] [optional] The pattern is not used for a read-only report that can safely project directly to a DTO
- [ ] [recommended] No claim of faster, safer, or lower-memory behaviour is made without a measurement or test

## Before Returning

- [ ] [critical] Relevant build or type-check completed and output is reported honestly
- [ ] [critical] Unit tests cover invariant construction and state transitions
- [ ] [critical] Integration tests cover controller bypass, job caller, and cross-tenant access
- [ ] [recommended] Query-count and exact-response-shape tests run where applicable
- [ ] [recommended] Temporary files removed, including `.gitkeep`
- [ ] [critical] Anything unverifiable at runtime is stated as a limitation, not marked pass
