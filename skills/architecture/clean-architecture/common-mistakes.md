# Common Mistakes

These failures look like clean architecture because the folders are present. The fix works only
when it changes who can call what, not when it adds another comment.

## The controller is the authorization boundary

```typescript
// Only HTTP calls are guarded; jobs and message handlers call the service directly.
router.delete("/users/:id", requireAdmin, async (req, res) => {
  await deleteUser.execute(req.params.id);
  res.sendStatus(204);
});
```

The controller knows the transport, not every entry point. `A01:2025`, `CWE-602`.

Fix: `execute(actor, id, ct)` and decide in the use case. A missing actor is a compiler error.
The residual gap is the factory that creates system actors; restrict and audit it.

## Authentication mistaken for authorization

```csharp
[Authorize]
public Task<Order> Get(Guid id) => _orders.GetAsync(id); // authenticated, not owner-checked
```

A valid identity does not make every object theirs. `A01:2025`, `API1:2023`, `CWE-639`.

Fix: `FindForTenantAsync(id, actor.TenantId, ct)` inside the use case or port. Return the same
not-found result for missing and not-owned rows, so object existence is not confirmed.

## The use case accepts an ID but no actor

```python
class RefundOrder:
    def execute(self, order_id: int):
        return repo.find(order_id).refund()
```

There is no value from which ownership or permission can be decided. A route guard may hide the
problem until a job or CLI invokes it. `A01:2025`, `CWE-1220`.

Fix: make `execute(actor, order_id)` the only signature. Do not add `actor=None`; optional
security context is an authorization bypass with nicer typing.

## The entity is an ORM model

```csharp
public class Invoice : DbContextEntity // framework import in the domain
{
    public decimal Total { get; set; }
    public string PasswordHash { get; set; } = "";
}
```

The domain now depends on the framework, and serialization or lazy loading can expose persistence
fields. `A01:2025`, `CWE-653`, `CWE-213`.

Fix: plain domain types inward; map ORM rows in the adapter and map entities to explicit output
DTOs in the use case. The residual gap is a reflection mapper that copies every new field.

## The interface is placed beside the adapter

```typescript
// infrastructure/order-repository.ts
export interface OrderRepository { find(id: string): Promise<OrderRow>; }
```

The interface now speaks in persistence types and forces the domain to know infrastructure. The
arrow points outward. `A01:2025`, `CWE-653`.

Fix: define `OrderRepository` in the application/domain package using domain return types; let
infrastructure implement it. Enforce project-reference direction in the build.

## A repository returns IQueryable

```csharp
public interface IOrderRepository
{
    IQueryable<OrderRow> Query(); // caller controls filters and execution
}
```

The caller can omit the tenant predicate, and lazy navigation queries execute after the use case
boundary. `A01:2025`, `CWE-653`; lazy loading can also create `API4:2023` N+1 work.

Fix: intention-revealing methods with tenant and cancellation parameters, materialized inside the
adapter. The residual gap is a method implementation that ignores its tenant argument, so test
cross-tenant access.

## A DTO is a renamed entity

```typescript
return { ...user, passwordHash: undefined }; // the next sensitive field is exposed
```

Spreading is not mapping. It makes the entity schema the response contract and leaves over-fetching
at the mercy of future fields. `API3:2023`, `CWE-213`.

Fix: list every output field in a DTO literal. A new entity field then has no route into JSON.

## Validation exists only at the edge

```python
# HTTP schema rejects a negative balance; CSV import constructs the model directly.
class Account:
    def __init__(self, balance_cents: int):
        self.balance_cents = balance_cents
```

A second entry point creates an invalid aggregate. `A06:2025`, `CWE-20`.

Fix: private constructor plus `Account.open(...)` factory that rejects invalid state. Keep format
validation at the edge and invariant validation in the domain. Existing invalid database rows
still need a migration; the factory cannot repair history.

## Singleton holds request state

```csharp
services.AddSingleton<InvoiceUseCase>();
// InvoiceUseCase constructor receives ICurrentUser and AppDbContext.
```

The first actor can be retained and reused for every request, while the context, tracked entities,
and connection never leave the singleton graph. `A01:2025`, `CWE-488`; resource retention is
also a performance finding.

Fix: register the use case and context as scoped. For a singleton worker, create and dispose a
scope per job. Enable scope validation; .NET detects scoped services injected into singletons in
the development provider. A factory delegate or static can still evade that check.

## A singleton use case caches a lookup in an instance field

```typescript
class GetPlan {
  private plan?: Plan; // one tenant's plan becomes every tenant's plan
  async execute(actor: Actor) {
    return this.plan ??= await this.repo.byTenant(actor.tenantId);
  }
}
```

This is stale authorization and an unbounded retained reference if the field grows into a map.
`A01:2025`, `CWE-488`.

Fix: make the use case scoped and use an injected bounded cache whose key includes tenant, or do
not cache. The cache's TTL and maximum belong in configuration and tests.

## The adapter invents cancellation

```csharp
public interface IEmailPort { Task SendAsync(Message message); }
// Adapter chooses no timeout because the port never mentions one.
```

A slow provider retains every request's graph until its socket timeout, if one exists. `A06:2025`,
`API4:2023`, `CWE-770`.

Fix: put `CancellationToken` in every I/O port method; link the caller's token to an adapter-owned
budget. The remaining gap is unbounded response content, which needs a limited stream.

## The happy path owns disposal

```python
context = make_context()
result = context.query()       # exception here skips close()
context.close()
```

Connections and tracked entities survive the error path. `A06:2025`, `CWE-772`.

Fix: `with make_context() as context:` or `try/finally`. If a DI container created the object, let
that container dispose it at scope end; if your code created it, your code owns the release.

## Every aggregate gets a repository, and every row loads children

```typescript
for (const order of await orders.list(actor.tenantId)) {
  order.customer = await customers.byId(order.customerId); // 1 + N
}
```

At 100 rows this is 101 round trips before any response mapping. `API4:2023`, `CWE-1050`.

Fix: batch by IDs or use a read-model projection. Assert query count. Do not solve an N+1 by
returning IQueryable; that reopens the tenant boundary.

## Layers are folders, not dependency direction

```text
src/
  entities/       # imports Prisma and Express
  use-cases/      # calls the database directly
  adapters/       # imports use-case internals
```

Names do not create a boundary. `A06:2025`, `CWE-653`.

Fix: enforce project references or import-linter rules and test that domain files compile without
the framework. A diagram without an enforcement mechanism is a wish.

## A reflection mapper silently widens output

```csharp
return _mapper.Map<MemberDto>(entity); // convention copies a newly added sensitive property
```

The mapper may be convenient while making the DTO a mirror rather than an allowlist. `API3:2023`,
`CWE-213`.

Fix: configure an explicit member list or write the mapping. Add a test that asserts the exact
JSON keys. If configuration is not verified, state that limitation.

## A read-only report loads full aggregates

```python
orders = order_repo.list_for_tenant(actor.tenant_id)  # builds 10,000 domain objects
return [OrderRow.from_order(o) for o in orders]
```

The report needs five columns but retains every entity and value object until the unit of work
ends. `API4:2023`, `CWE-770`.

Fix: a read port projects directly to a DTO with a server-side page limit. Read paths do not need
an aggregate merely because write paths do.

## Catching a security failure and continuing

```typescript
try {
  await policy.check(actor, target);
} catch {
  return performMutation(); // outage becomes authorization grant
}
```

The dependency outage is now the cheapest bypass. `A10:2025`, ASVS V16.

Fix: deny or return an explicit unavailable result, log the decision without secrets, and do not
turn a 503 into a 403. Narrow the catch so programming errors are not swallowed.
