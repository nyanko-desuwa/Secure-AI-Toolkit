# Common Mistakes

What goes wrong in real DDD codebases, and in AI-generated ones. Each entry: the shape, why
it fails, the fix, and why the fix holds rather than depending on the next author being
careful.

## Two contexts sharing a table

Billing reads `orders` directly because "the data is right there". Six months later Sales
renames `orders.customer_id` to `orders.buyer_id` in a migration, or changes it from the
customer's ID to the billing account's ID. Billing's query still compiles. Its tenant filter
now filters on the wrong column value.

Why it fails: there is no boundary. A boundary you can bypass with a `SELECT` is
documentation. `CWE-653`, `CWE-1220`, `A01:2025`.

Fix: one schema per context, one DB role per context, grants that make the cross-read
impossible. Cross-context reads go through a published contract.

Why it holds: the database refuses the query. Nobody has to remember the rule.

## Anemic aggregate - public setters plus a service that validates

```typescript
class Order {
  status: string = "draft";
  lines: OrderLine[] = [];
}

class OrderService {
  submit(order: Order) {
    if (order.lines.length === 0) throw new Error("empty order");
    order.status = "submitted";
  }
}
```

The rule "a submitted order has at least one line" lives in `OrderService`. Any other code
with an `Order` reference can write `order.status = "submitted"`. Admin tooling, an importer,
a retry job - each is a second write path, and each is written by someone who never read
`OrderService`.

Fix: private state, behaviour methods, the invariant checked inside the aggregate. See
[best-practices.md](best-practices.md#invariants-live-inside-the-boundary).

Why it holds: the illegal transition is not expressible. `order.status = ...` stops
compiling, so the bypass is a compile error rather than a code review miss.

## Invariant that spans two aggregates, checked in memory

```python
account = accounts.get(account_id)
total = sum(o.amount for o in orders.for_account(account_id))
if total + amount > account.credit_limit:
    raise CreditLimitExceeded()
orders.add(Order(account_id, amount))
```

Two concurrent requests both read the same total, both pass, both insert. The limit is
exceeded and no line of code was wrong in isolation. `CWE-362`.

Fix: either the limit belongs inside one aggregate that holds the running total and is
written under one optimistic-concurrency version, or it is a database constraint, or you
accept eventual consistency and define the compensating action. Pick one and write it down.

Why it holds: a version check or a constraint makes the second writer fail. An in-memory
check cannot, because the window between read and write is where the failure lives.

## Aggregate sized by the ER diagram

`Order` holds every `OrderLine`, plus the `Customer`, plus an `Inventory` snapshot, because
that is how the tables join. Changing a delivery note loads several hundred rows and rewrites
them. Two users editing unrelated lines collide on the version check.

Fix: size the aggregate by what must be transactionally consistent. Reference other
aggregates by ID. Reads that need the joined shape get a query model -
`skills/architecture/cqrs/`.

Why it holds: contention is proportional to aggregate size. A smaller aggregate has fewer
concurrent writers by construction, and the read path stops paying write-model costs.

## Primitive `string` IDs in adjacent positions

```typescript
function loadDocument(tenantId: string, userId: string): Promise<Doc>
loadDocument(user.id, tenant.id); // compiles, wrong order
```

This is not hypothetical tidiness. The query runs with a user ID in the tenant slot, the
filter matches nothing or - worse, where IDs collide across namespaces - matches another
tenant's rows.

Fix: branded or nominal ID types. `TenantId` and `UserId` are not assignable to each other.

Why it holds: the type checker rejects the swap. Naming conventions and parameter order
discipline do not survive a refactor.

## Validation at the call site instead of in the type

```python
if "@" in email and len(email) < 255:
    users.create(email)
```

There are eleven call sites. Ten validate. The eleventh is an admin importer written in a
hurry. Now an unvalidated address is in the database and every downstream consumer inherits
the assumption that it was checked.

Fix: an `Email` value object whose constructor is the only way to obtain one. Parse at the
boundary, pass the type inward.

Why it holds: an invalid instance cannot be constructed, so no call site can skip the check.
`ASVS V2`.

## Domain event carrying the whole entity

```typescript
bus.publish({ type: "UserRegistered", user });
```

`user` has `passwordHash`, `mfaSecret`, `internalRiskScore`, and `isEmployee`. It goes to
every consumer and into whatever logs the bus writes. `A01:2025`, `A09:2025`, `CWE-200`.

Fix: an explicit event type with named fields, constructed from the aggregate rather than
spreading it.

Why it holds: adding a field to the entity no longer changes the event payload. The leak
required no malice, only a later migration; the explicit type removes that coupling.

## Consumer trusting the event as authorization

```typescript
on("InvoiceApproved", async (e) => {
  await payments.disburse(e.invoiceId, e.amount);
});
```

Whoever can publish to the bus can move money. Any producer bug, any replay of an old
message, any misconfigured topic becomes a payment. `A01:2025`, `CWE-863`.

Fix: the handler re-checks its own preconditions against its own state - invoice exists, is
in an approvable state, approver still holds the role, not already disbursed.

Why it holds: authorization is decided by the component that owns the consequence. The event
becomes a trigger to check, not a permission.

## Events published before commit

```csharp
_bus.Publish(new OrderSubmitted(order.Id));
await _db.SaveChangesAsync();
```

If `SaveChangesAsync` throws, the consumer already acted on an order that does not exist.
Under an in-process synchronous bus the handler may even run inside the same transaction and
read uncommitted state. `CWE-662`.

Fix: aggregates record events; the unit of work dispatches after commit, or writes to an
outbox in the same transaction.

Why it holds: commit is the point where the state became real. Ordering the publish after it
means a consumer can never observe a state the database rolled back. Accept and document
at-least-once delivery - make handlers idempotent.

## Handler subscribed in a constructor, never removed

```typescript
class OrderProjection {
  constructor(private bus: EventBus, private db: Db) {
    bus.on("OrderSubmitted", (e) => this.apply(e));
  }
}
```

Instantiated per request or per tenant, this grows the listener list forever. Each closure
retains `this`, `db`, and everything else in scope. The symptom is a slow heap climb plus
handlers firing N times for one event. `CWE-401`, and the duplicate dispatch is a correctness
bug too.

Fix: subscription returns a disposer; ownership is explicit and release is tied to the host's
shutdown or the scope's disposal. Registration happens once at composition, not in a
per-request object.

Why it holds: the API returns something you must hold, so forgetting to release becomes
visible at the call site. See `skills/architecture/performance/` for the heap-level detail.

## Repository returning a query object

```typescript
class OrderRepository {
  query() { return this.db.selectFrom("orders"); }
}
```

Callers now write their own `where` clauses, including the tenant filter. One of them
forgets. The repository's job was to be the only place that knows how orders are fetched, and
it delegated that job to every caller.

Fix: repository methods take the scope as a parameter and return whole aggregates. If a
report needs a projection, that is a read model, not a repository leak.

Why it holds: the tenant predicate is applied by code that cannot be skipped, because the
only entry point requires the scope argument.

## Repository handing back the ORM entity

The caller gets a tracked entity, mutates a property, and the unit of work saves it. Every
invariant in the aggregate was bypassed, silently, with no method call to review. `CWE-284`.

Fix: map the persistence model to the aggregate at the repository boundary, or use ORM
features that keep state private (backing fields, private setters) so the entity *is* the
aggregate.

Why it holds: mutation requires calling a method, and the methods enforce the invariants.

## Lazy loading inside the domain

An aggregate method touches `order.customer.address.country` and triggers a query. Now domain
logic depends on an open session, is untestable without a database, and produces N+1 patterns
under iteration.

Fix: load what the operation needs, explicitly, before invoking domain logic. Reference other
aggregates by ID and fetch them deliberately.

Why it holds: no hidden IO means no surprise query count, and the aggregate stays a pure
object you can construct in a test.

## Ubiquitous language treated as a security control

Renaming a class to match business vocabulary reduces misunderstanding. It does not enforce
anything. Do not put "aligned the ubiquitous language" in a security section - it belongs in
maintainability, and claiming otherwise makes the rest of the report less credible.

## DDD applied where there is no domain

Six folders, an `IOrderRepository` with one implementation, an `OrderCreatedEvent` with no
subscriber, and a service that calls a repository that calls an ORM - to save a form. The
authorization question now takes four files to answer.

Fix: a validated request DTO, one query with the ownership predicate, one table. Add
structure when an invariant demands it.

Why it holds: fewer indirections means the security-relevant line is visible. See
[troubleshooting.md](troubleshooting.md#when-not-to-use-ddd).
