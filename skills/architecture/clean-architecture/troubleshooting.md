# Troubleshooting

Use this when the dependency rule conflicts with the codebase, the framework, or the measured cost.
Do not solve a mismatch by adding another layer whose purpose nobody can name.

## The project already mixes every layer

Do not reorganize the repository in one sweep. Pick one security-relevant vertical slice:
controller, use case, repository, entity, response. Move the enforcement points first.

1. Add the actor to the use case signature.
2. Move the permission decision into it.
3. Add an explicit output DTO.
4. Put one repository port inward and implement it outward.
5. Add a dependency-direction test before moving the next slice.

A big-bang folder move produces a huge diff where imports change but security behaviour cannot be
reviewed. The incremental slice leaves both architectures temporarily present; state that debt
and prohibit new code on the old path.

## The framework wants ORM annotations on entities

You have three choices:

- Keep a separate persistence model and map. Strongest boundary, highest mapping cost.
- Put persistence annotations on the domain entity but prohibit ORM APIs in domain methods.
  Weaker boundary, lower cost; annotations become a compile-time framework dependency.
- Accept an active-record domain for a CRUD application. Do not call it Clean Architecture.

Choose by whether the domain rules need to outlive or be tested without the ORM. Do not create a
second model by reflex for a table with two fields and no invariant.

## The repository interface has one implementation

Delete it unless it earns its keep. It earns its keep if one of these is true:

- the inner project otherwise cannot compile without importing infrastructure;
- its method signature pins a security predicate such as tenant plus actor;
- tests need a deterministic implementation that is not a mock of an ORM query;
- a second implementation exists or is scheduled, not merely imaginable.

An interface around every class is not inversion; it is navigation tax.

## Authorization needs data from two aggregates

The use case still owns the decision. Fetch the minimum facts through two ports or a dedicated
policy read port. Do not move the rule to the controller because the query is inconvenient.

Watch the cost: two ports called in a loop become N+1. Batch the facts or create one read model
that returns the policy inputs in one query. The read model may join tables across aggregates; it
must still scope by actor or tenant and return only facts, not mutable aggregates.

## A policy is shared across many use cases

Extract a domain policy object only when the rule truly is the same. The use case still invokes
it with actor and intent-specific facts. Do not create a generic `AuthorizationService.can(actor,
action, resource)` that hides every rule behind strings; reviewers can no longer see what a use
case requires, and `CWE-1220` granularity drifts.

Keep the default deny. An unknown action is denied, not allowed.

## Background work has no end-user actor

That does not mean authorization is optional. Give the job its own principal:

- a system actor with explicit permissions and tenant;
- a delegated actor captured from the original command, if policy permits and staleness is handled;
- a service identity mapped to a narrow operation.

Record which principal caused the mutation. Restrict construction of system actors and audit it.
Never reuse the last HTTP actor from ambient request state.

## The serializer already hides sensitive fields

Treat serializer annotations as defence in depth, not the response contract. Verify the exact
runtime behaviour and version, then still build an explicit output DTO when property-level
authorization matters. A serializer cannot decide whether this actor may see this email because
it does not know the business intent.

If mapping cost is genuinely hot, project the database query directly into the DTO. Do not return
the entity to save one allocation.

## Mapping dominates the profile

First prove it with a profile under representative payload size. If the mapper is hot:

1. replace reflection or convention mapping with generated or hand-written mapping;
2. project read queries directly into DTOs;
3. avoid constructing aggregates on read-only paths;
4. page the result;
5. compare allocations and latency before and after.

Do not delete output DTOs. That trades a measured CPU cost for an unbounded response schema.
Below a few hundred objects per response, database and JSON costs usually dominate, but your
measurement wins over this rule of thumb.

## Repositories create N+1 queries

Count before fixing. A page of 100 orders plus one customer query per order is 101 queries; adding
one invoice query per order is 201. Choose one:

- batch child IDs: usually 2 to 3 queries;
- eager load one bounded relationship: often 1 query, but can multiply rows;
- dedicated read model: 1 projection query, strongest for reports;
- data-loader style request cache: bounded to the request, not a singleton.

Assert the count in a test. Returning an ORM query object is not a fix; it moves query construction
past the boundary and makes tenant filtering optional.

## The container rejects a captive dependency

Believe it. Do not turn off scope validation.

- Make the consuming service scoped if it handles request data.
- If the consumer must be a singleton worker, inject a scope factory and resolve per job.
- Move process-lifetime state into a separate bounded singleton cache keyed by tenant.
- Pass the actor as a method parameter rather than capturing it.

If the exception appears only in Development, add a CI boot test using the same validation mode.
Production being permissive is not evidence the graph is safe.

## The container does not reject a captive dependency

Draw the graph yourself. An object may depend only on something whose lifetime is at least as long
as its own. Search singleton constructors and factory closures for request, tenant, actor,
`DbContext`, session, connection, cursor, and unit-of-work types. Verify disposal ownership.

Add a regression test that resolves two request scopes with different tenants and proves that the
instances and results differ. Then use a heap profiler if retained references are suspected; see
`skills/architecture/performance/` for that diagnosis.

## Cancellation does not exist in the current port

Changing the signature is worth the break. Add the token/deadline at the entry point and thread it
through use cases and every I/O port. Do not fetch a global request token in the adapter — that is
ambient request state and fails in jobs.

The adapter adds its own dependency budget by linking tokens. The use case chooses what a timeout
means: retry, return unavailable, compensate, or fail. Authorization errors and timeout errors
must remain distinct.

## A unit test becomes difficult after moving the check

That usually exposes an implicit dependency. Construct an explicit `Actor`, inject deterministic
ports, and test the outcome. Do not mock `HttpContext` just to test a business permission; the
point of the move is to make HTTP irrelevant.

Test one controller separately for credential-to-actor translation. Test every use case for actor
plus intent. This produces fewer, stronger tests than repeating role guards on routes.

## The database has row-level security already

Keep use-case authorization. Database RLS answers which rows the session may see; it usually does
not know whether the operation is self-approval, exceeds a limit, or violates separation of
duties. The layers are complementary:

- use case: actor plus intent;
- repository: intention-revealing query;
- database: tenant row isolation below every query.

Be explicit about how tenant context reaches the database connection and resets before pool reuse.
A stale session variable is the database version of a captive dependency.

## Clean Architecture is wrong for this feature

Say so and simplify. A CRUD endpoint with no domain rule can be a thin controller plus a scoped,
tenant-filtered query and explicit response fields. A report can be SQL straight to a DTO. A
script can have one visible authorization check.

The security requirement survives simplification: actor-derived tenant, explicit writable and
readable fields, bounded query, scoped connection, timeout. Four folders are not the control.

## Runtime behaviour cannot be verified from source

State the unknown and the command or test that would answer it. Examples:

- "Scope validation appears enabled in Development; I did not boot the app to confirm."
- "The adapter passes cancellation, but the third-party client may ignore it."
- "The query is eager in source; query count is unconfirmed without SQL logging."
- "The DTO lists fields explicitly; deployed serializer configuration was not inspected."

Unverified is not secure or insecure. It is unverified.
