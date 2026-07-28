# DDD Troubleshooting

What to do when the pattern does not fit, the model is incomplete, or the secure boundary
conflicts with an existing constraint.

## When NOT to Use DDD

A CRUD app with no invariants gains nothing from aggregates and loses clarity.

If the feature is:

1. parse a request,
2. verify the actor owns the row,
3. insert or update the row,
4. return a response,

then a table plus a validated request is the right answer. Put the tenant or owner predicate
in the query. Do not add an aggregate root, repository interface, domain service, event, and
handler to say `UPDATE profile SET display_name = ? WHERE id = ? AND tenant_id = ?`.

The cost is not abstract. Five files instead of one make the authorization predicate harder
to locate. A unit-of-work tracks objects that could have been updated directly. An event bus
adds handler lifetime and commit-ordering problems to a feature with no consumer. Vocabulary
and folders are not value.

Use DDD when at least one of these is true:

- A business rule spans multiple values and must hold after every write
- More than one write path must obey the same transition rule
- The same word means different things in parts of the business
- An external model must not leak into your own
- A boundary has a security or team-ownership consequence you can enforce

Otherwise take the smaller design. Partial adoption is valid: branded ID types and a scoped
query can be right while aggregates and domain events are wrong.

## The Domain Expert Is Unavailable

Do not invent the domain and call it modelling. Generated code is especially confident about
rules nobody stated.

Use an evidence ladder:

1. Current production behaviour, including error paths
2. Database constraints and migrations
3. User-facing wording and support runbooks
4. Tests that express business outcomes
5. Audit logs showing real transitions
6. Names in current code, last — they may already be wrong

Write hypotheses as hypotheses:

```text
Assumption DDD-04: a submitted order cannot receive new lines.
Evidence: API returns 409; database has no constraint; batch importer is unknown.
Owner needed: fulfilment operations.
Risk if wrong: importer rejects a legitimate post-submit adjustment.
```

Model only what the evidence supports. Put uncertain rules behind an explicit policy
interface rather than baking them into twelve entities. Do not create fake certainty with a
rich class hierarchy.

Security exception: ownership and tenant isolation do not wait for a domain expert. Derive
the actor from the authenticated context and scope every query. That is authorization, not a
business-language question (`A01:2025`, ASVS V8).

## The Existing Schema Fights the Aggregate Boundary

A schema designed for reporting often joins everything and exposes public foreign keys. Do
not make the domain object graph match it.

Choose the least disruptive option that makes the boundary real:

| Constraint | Approach | Cost |
|---|---|---|
| One database, schema changes allowed | Separate schemas and DB roles; views for cross-context reads | More roles and pools |
| One database, schema fixed | Repository mapping plus deny raw ORM access outside the module | Boundary enforced by code, weaker than grants |
| Shared table cannot move yet | Create an owner service; other context reads a compatibility view/API; migrate writes first | Dual-read period and operational work |
| Legacy primary keys are primitive | Translate them to typed IDs in the repository/ACL | Mapping code on every load |
| ORM requires public setters | Use backing fields/private setters, or map persistence rows to domain objects | More mapping and possible full-row writes |

Migrate ownership in this order:

1. Inventory every writer, including jobs and ad hoc scripts.
2. Name one context as the table owner.
3. Route all other writes through the owner's contract.
4. Give non-owners read-only compatibility access if needed.
5. Remove that read access after projections or APIs are stable.
6. Revoke database grants. The last step is what makes the boundary real.

Do not do a flag-day database split unless the risk requires it. The temporary shared table
is an explicit residual risk with an owner and an end date; pretending it is already a
bounded context is worse.

## A Bounded-Context Split Would Require a Distributed Transaction

This usually means one of three things:

- The boundary is wrong and the invariant belongs in one context
- The operation is two local transactions with a compensating action
- The business requires atomicity strongly enough that the split does not earn its cost

Start with the invariant. If `reserve inventory and accept order` must be all-or-nothing by
business definition, keeping them in one context may be the honest design. A context boundary
is not automatically worth weakening correctness.

If the split is real, make the intermediate state a domain state, not an accident:

```text
Order: PendingReservation -> Accepted | RejectedInventoryUnavailable
Inventory: reservation command is idempotent by orderId
Timeout: PendingReservation older than 2 minutes -> RejectedReservationTimedOut
Compensation: release reservation if payment later fails
```

Then specify:

- who owns the workflow state,
- how duplicate messages are detected,
- what the user sees while pending,
- timeout and retry budget,
- what is logged for an auditor,
- what happens if compensation also fails.

That is eventual consistency as a correctness cost. If nobody can answer those questions,
keep the transaction local and do not split yet.

## The Aggregate Is Too Large

Measure before redesigning. Record for the hot command:

- rows and bytes loaded,
- rows written,
- p95 duration,
- optimistic-concurrency conflict rate,
- peak retained entities in the unit of work.

Then use the symptom to choose the fix:

| Symptom | Fix |
|---|---|
| Reads load the whole graph | Read projection / CQRS; do not shrink a correct write boundary for reads |
| Unrelated writes collide | Split where no invariant crosses; reference by ID |
| One invariant needs all 20 000 children | Maintain a root summary under a DB constraint/version, and audit reconciliation |
| Unit of work retains thousands of roots | Shorten the scope; clear tracking between batches |

The read/write split belongs in `skills/architecture/cqrs/`. Heap and retained-reference
diagnosis belongs in `skills/architecture/performance/`.

## The Aggregate Needs Data from Another Aggregate

Do not pass a mutable `Customer` into `Order` and make both part of one graph by convenience.
Pass an immutable value the rule needs — for example `CreditLimit` — or let the application
service load both roots and pass the decision input into one root's method.

State the staleness window. A copied credit limit can change after it is read. If that is
unacceptable, the two pieces of state may be one aggregate, or the database must enforce the
rule, or the command must tolerate a concurrency failure and retry.

## The Repository Needs a Flexible Query

That is a read-side query, not a repository method.

Keep command repositories narrow: `find(tenant, id)`, `save(aggregate)`. Put sorting,
faceting, joins, and report filters into a query service that returns an immutable DTO and
requires tenant scope. Do not return `IQueryable` merely to avoid writing methods — that
moves the authorization boundary to every caller.

## Events Are Slow or Handlers Accumulate

First separate two failures:

- Slow request immediately after publishing: a synchronous handler is doing I/O inside the
  command path. Move it behind a post-commit outbox.
- Memory and duplicate callbacks grow with uptime: handlers are registered repeatedly and
  never removed. Register once at host start or retain a disposer and release with the
  scope.

Bound queue depth and choose what happens at the bound: reject, block, or shed lower-priority
work. An unbounded in-process dispatcher is not resilient because it has no backpressure.
Use `skills/architecture/performance/` for heap snapshots; source alone cannot prove which
object retains a handler.

## The Framework Already Manages Commit Ordering, Allegedly

Verify the version and the configuration. Ask:

- Does "after commit" mean after the database transaction commits, or after `SaveChanges`?
- What happens if the process crashes between commit and publish?
- Is delivery at-most-once or at-least-once?
- Does the dispatcher preserve ordering per aggregate?
- How are subscriber failures retried and bounded?

If you cannot confirm those answers from pinned documentation or a test that kills the
process in the crash window, say so. Do not call an in-memory post-save hook an outbox.

## DDD Terminology Conflicts with the Existing Team

Prefer the team's domain words inside its context. Do not rename `Policy` to `Contract`
because a book uses that word if the business says `Policy`. The exception is a word used
for two meanings inside one context; qualify it or split the context.

Create a short glossary beside the code or in an ADR. Language drift is a maintainability
problem. It becomes a security problem only when the drift changes which actor, tenant, or
resource a rule applies to. Report the consequence, not the vocabulary disagreement.
