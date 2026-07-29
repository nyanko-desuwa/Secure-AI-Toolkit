# Clean Architecture Examples

Eight before/after pairs. Each one names the category, the CWE where one applies, the failure in
one sentence, the fix, why the fix removes the option rather than relying on discipline, and the
residual gap.

Read them as structural patterns. The language is incidental; the misplaced enforcement point is
not.

## Contents

- [Entity serialized straight to JSON](#entity-serialized-straight-to-json) - A01, API3:2023, CWE-213
- [Authorization only in the controller](#authorization-only-in-the-controller) - A01, CWE-602
- [Use case with an ID and no actor](#use-case-with-an-id-and-no-actor) - A01, CWE-1220
- [Singleton capturing a request-scoped user](#singleton-capturing-a-request-scoped-user) - A01, CWE-488
- [Invariant in a boundary validator, not the entity](#invariant-in-a-boundary-validator-not-the-entity) - A06, CWE-20
- [Repository returning IQueryable](#repository-returning-iqueryable) - A01, CWE-653
- [Domain importing the ORM, tenant filter in infrastructure](#domain-importing-the-orm-tenant-filter-in-infrastructure) - A01, CWE-653
- [Port with no timeout or cancellation](#port-with-no-timeout-or-cancellation) - A06, API4:2023, CWE-770

---

## Entity serialized straight to JSON

`A01:2025` · `API3:2023` · `CWE-213` · ASVS V8, V14

The use case returns the ORM entity, so every column on the table - including
`passwordHash` and internal flags - is serialized into the response.

```typescript
// Vulnerable: the response shape is whatever the table has today
// src/application/get-member.ts
export class GetMember {
  constructor(private readonly prisma: PrismaClient) {}

  async execute(memberId: string) {
    return this.prisma.member.findUnique({ where: { id: memberId } });
  }
}

// src/http/members.controller.ts
router.get("/api/members/:id", requireAuth, async (req, res) => {
  const member = await getMember.execute(req.params.id);
  if (!member) return res.status(404).json({ error: "not_found" });
  res.json(member);
});
```

The Prisma model has `passwordHash`, `mfaSecret`, `isInternal`, `riskScore`, and
`stripeCustomerId`. All five reach the client. Nobody wrote a line that exposes them; the
absence of a mapping step did.

```typescript
// Fixed: the use case builds an explicit view. Fields are an allowlist by construction.
// src/application/get-member.ts
export interface MemberView {
  id: string;
  displayName: string;
  email: string;
  joinedAt: string;
}

export class GetMember {
  constructor(private readonly members: MemberRepository) {}

  async execute(actor: Actor, memberId: string): Promise<MemberView | null> {
    const member = await this.members.findInTenant(memberId, actor.tenantId);
    if (!member) return null;

    const selfOrAdmin = actor.userId === member.id || actor.can("member:read_contact");
    return {
      id: member.id,
      displayName: member.displayName,
      email: selfOrAdmin ? member.email : "",
      joinedAt: member.joinedAt.toISOString(),
    };
  }
}
```

Why it removes the option: adding a column to the table cannot change the response, because
nothing copies unnamed fields. The alternative - a deny list, `omit: { passwordHash: true }` or
`@Exclude()` - inverts the default, so the next sensitive column is public until someone
remembers it.

Residual gap: the DTO is a compile-time allowlist, not a runtime guarantee about nesting. If
`MemberView` later carries a nested object built by spreading an entity, the leak returns. Assert
the response shape in a test - snapshot the JSON keys, not just the status code.

---

## Authorization only in the controller

`A01:2025` · `CWE-602` · ASVS V8

The permission check lives in the HTTP layer, so a background job calling the same service
performs the action with no check at all.

```csharp
// Vulnerable: the guard is on the route, the service is unprotected
// Web/PayoutsController.cs
[HttpPost("payouts/{id}/release")]
public async Task<IActionResult> Release(Guid id, CancellationToken ct)
{
    if (!User.HasClaim("perm", "payout:release")) return Forbid();
    await _payouts.ReleaseAsync(id, ct);
    return NoContent();
}

// Application/PayoutService.cs
public sealed class PayoutService
{
    public async Task ReleaseAsync(Guid payoutId, CancellationToken ct)
    {
        var payout = await _db.Payouts.SingleAsync(p => p.Id == payoutId, ct);
        payout.Status = PayoutStatus.Released;
        await _db.SaveChangesAsync(ct);
    }
}

// Jobs/StuckPayoutRetryJob.cs - added six months later, by someone else
foreach (var id in stuckIds)
    await _payouts.ReleaseAsync(id, ct);     // no claim, no tenant, no audit actor
```

The job is not wrong on its own terms. It calls a public method with the argument the method
asks for. The check was never part of the contract, so there was nothing to omit.

```csharp
// Fixed: the use case takes the actor and decides. The signature enforces it.
public sealed class ReleasePayout
{
    private readonly IPayoutRepository _payouts;
    private readonly IAuditLog _audit;

    public ReleasePayout(IPayoutRepository payouts, IAuditLog audit)
        => (_payouts, _audit) = (payouts, audit);

    public async Task<ReleaseOutcome> ExecuteAsync(
        Actor actor, Guid payoutId, CancellationToken ct)
    {
        if (!actor.Permissions.Contains("payout:release"))
        {
            await _audit.DeniedAsync(actor, "payout:release", payoutId, ct);
            return ReleaseOutcome.Denied;
        }

        var payout = await _payouts.FindForTenantAsync(payoutId, actor.TenantId, ct);
        if (payout is null) return ReleaseOutcome.NotFound;

        payout.Release(actor.UserId);                       // invariant lives in the entity
        await _payouts.SaveAsync(payout, ct);
        await _audit.PerformedAsync(actor, "payout:release", payoutId, ct);
        return ReleaseOutcome.Released;
    }
}

// Jobs/StuckPayoutRetryJob.cs - must now name a principal
var actor = Actor.System(tenantId, permissions: new[] { "payout:release" });
foreach (var id in stuckIds)
    await _releasePayout.ExecuteAsync(actor, id, ct);
```

Why it removes the option: `ExecuteAsync(id, ct)` does not compile. The job author cannot reach
the operation without producing an `Actor`, and `Actor.System(...)` is a greppable, reviewable,
auditable decision instead of an invisible omission. The audit entry now has a subject for every
release, including automated ones.

Residual gap: `Actor.System` is a legitimate elevation path. Restrict who can construct it -
`internal` to the job assembly, or a factory that requires a configured job identity - and alert
on its use. Without that, you have moved the bypass rather than closed it.

---

## Use case with an ID and no actor

`A01:2025` · `CWE-1220` · ASVS V8

The use case accepts a document ID and a tenant ID from the caller, so ownership cannot be
checked and a caller who supplies another tenant's ID reads its data.

```python
# Vulnerable: both IDs come from the request, so the pair is never verified
class ExportDocument:
    def __init__(self, docs: DocumentRepository) -> None:
        self._docs = docs

    def execute(self, document_id: int, tenant_id: int) -> bytes:
        doc = self._docs.find(document_id, tenant_id)
        return render_pdf(doc)

@app.post("/api/documents/<int:doc_id>/export")
def export_document(doc_id: int):
    body = request.get_json(force=True)
    return export.execute(doc_id, body["tenantId"])     # client picks the tenant
```

The repository call looks scoped. It is not: the scope is an attacker-supplied value. This is the
shape that survives review, because the `WHERE tenant_id = %s` is present and correct.

```python
# Fixed: the actor is the only source of identity, and it is required
from dataclasses import dataclass

@dataclass(frozen=True)
class Actor:
    user_id: int
    tenant_id: int
    permissions: frozenset[str]

    def can(self, permission: str) -> bool:
        return permission in self.permissions

class ExportDocument:
    def __init__(self, docs: DocumentRepository, audit: AuditLog) -> None:
        self._docs = docs
        self._audit = audit

    def execute(self, actor: Actor, document_id: int) -> bytes:
        if not actor.can("document:export"):
            self._audit.denied(actor, "document:export", document_id)
            raise PermissionDenied()

        doc = self._docs.find_in_tenant(document_id, actor.tenant_id)
        if doc is None:
            raise NotFound()          # not-yours and not-found are indistinguishable
        return render_pdf(doc)

@app.post("/api/documents/<int:doc_id>/export")
def export_document(doc_id: int):
    actor = actor_from_verified_session()      # derived from the session, not the body
    return export.execute(actor, doc_id)
```

Why it removes the option: there is no parameter through which a caller can name a tenant. The
tenant is a property of the verified session, and the use case reads it from there. A future
caller who wants to act cross-tenant has to change the signature, which is a visible design
change rather than a forgotten check.

Residual gap: `actor_from_verified_session()` is now the whole boundary. If it falls back to a
header or a query parameter when the session is absent, the fix is undone. Test that an
unauthenticated request raises rather than producing an anonymous `Actor` with an empty tenant.

---

## Singleton capturing a request-scoped user

`A01:2025` · `CWE-488` · ASVS V7, V8

A singleton service takes the current user and the ORM context in its constructor, so the first
request's tenant is used for every later request and the object graph is never released.

```csharp
// Vulnerable: singleton lifetime, request-scoped dependencies
public sealed class ReportBuilder
{
    private readonly AppDbContext _db;        // scoped: not thread-safe, holds a connection
    private readonly ICurrentUser _user;      // request data
    private readonly Dictionary<int, string> _labelCache = new();

    public ReportBuilder(AppDbContext db, ICurrentUser user) => (_db, _user) = (db, user);

    public async Task<Report> BuildAsync(CancellationToken ct)
    {
        var rows = await _db.Sales
            .Where(s => s.TenantId == _user.TenantId)      // frozen at first resolution
            .ToListAsync(ct);
        return new Report(rows.Select(r => Label(r)).ToList());
    }

    private string Label(SaleRow r)
    {
        if (_labelCache.TryGetValue(r.ProductId, out var l)) return l;   // cross-tenant hit
        return _labelCache[r.ProductId] = _db.Products.Single(p => p.Id == r.ProductId).Name;
    }
}

builder.Services.AddSingleton<ReportBuilder>();          // the bug
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(cs));   // scoped by default
builder.Services.AddScoped<ICurrentUser, HttpCurrentUser>();
```

Three failures from one registration. Tenant A's ID is baked in, so tenant B receives tenant A's
sales - a cross-tenant data leak, not a caching quirk. The captured `AppDbContext` outlives its
scope, so a connection and the change tracker's entity graph are pinned for the process lifetime
and concurrent requests corrupt its state. `_labelCache` has no tenant in the key, no maximum
size, and no TTL, so it grows until the container is OOMKilled.

```csharp
// Fixed: scoped for anything touching request data, singleton only for the shared cache
public sealed class ReportBuilder
{
    private readonly AppDbContext _db;
    private readonly IProductLabelCache _labels;    // singleton, keyed and bounded

    public ReportBuilder(AppDbContext db, IProductLabelCache labels)
        => (_db, _labels) = (db, labels);

    public async Task<Report> BuildAsync(Actor actor, CancellationToken ct)
    {
        var rows = await _db.Sales
            .Where(s => s.TenantId == actor.TenantId)      // per-call, from the parameter
            .ToListAsync(ct);

        var labels = await _labels.GetManyAsync(
            actor.TenantId, rows.Select(r => r.ProductId).Distinct(), ct);
        return new Report(rows.Select(r => labels[r.ProductId]).ToList());
    }
}

builder.Services.AddScoped<ReportBuilder>();
builder.Services.AddSingleton<IProductLabelCache>(
    _ => new BoundedLabelCache(maxEntries: 50_000, ttl: TimeSpan.FromMinutes(10)));
```

For a hosted service or worker - a singleton by nature - inject `IServiceScopeFactory`, open a
scope per unit of work, resolve inside it, and dispose it:

```csharp
using var scope = _scopeFactory.CreateScope();
var builderForRun = scope.ServiceProvider.GetRequiredService<ReportBuilder>();
await builderForRun.BuildAsync(Actor.System(tenantId), ct);
```

Why it removes the option: the actor is a parameter, so there is nothing request-scoped left to
capture, and the only long-lived state is a cache whose key includes the tenant. The container
also catches this class of bug for you - .NET's default provider performs scope validation in
Development, verifying that scoped services are not resolved from the root provider and not
injected into singletons, and throws when `BuildServiceProvider` is called. Enable it in CI so
the failure is a red build, not a support ticket.

Residual gap: scope validation checks constructor injection. It cannot see a scoped object
smuggled in through a factory delegate, a static, or a captured closure. Heap-level detail on the
retention side lives in [`skills/architecture/performance/`](../../performance/best-practices.md)
(L1 unbounded cache, L6 request-scoped state stored globally).

---

## Invariant in a boundary validator, not the entity

`A06:2025` · `CWE-20` · ASVS V2

The rule that a discount cannot exceed the order subtotal is enforced by a request validator, so
the CSV importer creates orders that violate it.

```typescript
// Vulnerable: the invariant lives in the HTTP schema
const CreateOrderBody = z.object({
  subtotalCents: z.number().int().positive(),
  discountCents: z.number().int().nonnegative(),
}).strict().refine(b => b.discountCents <= b.subtotalCents, {
  message: "discount_exceeds_subtotal",
});

// domain/order.ts - accepts anything
export class Order {
  constructor(
    public readonly id: string,
    public readonly subtotalCents: number,
    public readonly discountCents: number,
  ) {}
  totalCents(): number { return this.subtotalCents - this.discountCents; }
}

// jobs/import-orders.ts - second entry point, no zod schema in sight
for (const row of parseCsv(file)) {
  await orderRepo.save(new Order(newId(), row.subtotal, row.discount));
}
```

The importer writes orders with negative totals. The refinement was correct and simply not on
the path the importer takes. Every fix applied to the schema leaves the importer broken.

```typescript
// Fixed: the constructor is private, so no path produces an invalid Order
export class Order {
  private constructor(
    readonly id: OrderId,
    readonly tenantId: TenantId,
    readonly subtotal: Money,
    readonly discount: Money,
  ) {}

  static place(input: {
    id: OrderId; tenantId: TenantId; subtotal: Money; discount: Money;
  }): Order {
    if (input.subtotal.cents <= 0) throw new DomainError("subtotal_must_be_positive");
    if (input.discount.cents < 0) throw new DomainError("discount_must_be_non_negative");
    if (input.discount.cents > input.subtotal.cents) {
      throw new DomainError("discount_exceeds_subtotal");
    }
    return new Order(input.id, input.tenantId, input.subtotal, input.discount);
  }

  total(): Money { return this.subtotal.minus(this.discount); }
}
```

The edge schema stays, doing the job it is good at: shape, types, ranges, and `.strict()` to
reject unknown keys (`CWE-915`). It no longer owns the business rule.

Why it removes the option: `new Order(...)` is unavailable outside the class. Both the HTTP
handler and the importer must call `Order.place`, and `place` cannot return an invalid instance.
The importer's bad rows now fail loudly at construction instead of persisting silently.

Residual gap: the rehydration path. Loading from the database must not re-run rules that older
rows already violate, so it needs its own factory (`Order.rehydrate`) that trusts persistence.
That factory is a hole by design - keep it out of the application layer's reach, and remember
that pre-existing invalid rows stay invalid until you migrate them.

---

## Repository returning IQueryable

`A01:2025` · `CWE-653` · ASVS V8, V15

The repository returns a composable query object, so a caller can build a query that never
applies the tenant filter, and lazy loading fires database calls after the boundary.

```csharp
// Vulnerable: the port exposes the persistence model
public interface IOrderRepository
{
    IQueryable<Order> Query();          // composable, unfiltered, lazily executed
}

public sealed class EfOrderRepository : IOrderRepository
{
    private readonly AppDbContext _db;
    public IQueryable<Order> Query() => _db.Orders;      // no predicate
}

// Application layer, six months later
public async Task<List<Order>> RecentAsync(CancellationToken ct)
    => await _orders.Query()
        .OrderByDescending(o => o.CreatedAt)
        .Take(50)
        .ToListAsync(ct);                                 // every tenant's orders
```

Two problems compound. The tenant predicate is optional because composition is the caller's job,
and `Order.Customer` is a lazy navigation, so serializing the result issues one query per row
after the use case has returned - outside the transaction, outside any timeout the use case set,
and against a context that may already be disposed.

```csharp
// Fixed: intention-revealing methods, filter inside, materialized results
public interface IOrderRepository
{
    Task<Order?> FindForTenantAsync(Guid orderId, Guid tenantId, CancellationToken ct);
    Task<IReadOnlyList<Order>> ListRecentForTenantAsync(
        Guid tenantId, int limit, CancellationToken ct);
    Task SaveAsync(Order order, CancellationToken ct);
}

public sealed class EfOrderRepository : IOrderRepository
{
    private readonly AppDbContext _db;
    public EfOrderRepository(AppDbContext db) => _db = db;

    public async Task<IReadOnlyList<Order>> ListRecentForTenantAsync(
        Guid tenantId, int limit, CancellationToken ct)
        => await _db.Orders
            .Where(o => o.TenantId == tenantId)          // not optional
            .Include(o => o.Customer)                    // eager: 1 query, not 1+N
            .OrderByDescending(o => o.CreatedAt)
            .Take(Math.Clamp(limit, 1, 200))             // server-side maximum
            .AsNoTracking()
            .ToListAsync(ct);
}
```

Why it removes the option: there is no method that returns something a caller can extend, so
there is no way to compose a query without the predicate. `ToListAsync` inside the repository
means every database call happens within the repository's transaction and timeout - nothing
lazily executes past the boundary. The clamped limit turns an unbounded result set into a
bounded one (`API4:2023`).

Residual gap: each new method needs the predicate written again, so the guarantee is per-method,
not global. Push it below the code with database row-level security, or add an EF Core global
query filter, and keep a test that asserts a cross-tenant read returns zero rows. `AsNoTracking`
is right for reads and wrong for the write path - do not copy it there.

---

## Domain importing the ORM, tenant filter in infrastructure

`A01:2025` · `CWE-653` · ASVS V8, V15

The domain package imports the ORM, so one use case queries the database directly and skips the
tenant filter that the repository applies.

```python
# Vulnerable: domain/billing.py imports the session and queries directly
from infrastructure.db import session          # the arrow points outward
from infrastructure.models import InvoiceRow

class InvoiceRepository:                       # lives in infrastructure
    def list_for_tenant(self, tenant_id: int) -> list[InvoiceRow]:
        return session.query(InvoiceRow).filter(InvoiceRow.tenant_id == tenant_id).all()

class SendDunningEmails:                       # lives in the domain, but imports the ORM
    def execute(self) -> int:
        overdue = (
            session.query(InvoiceRow)          # bypasses the repository entirely
            .filter(InvoiceRow.due_date < date.today(), InvoiceRow.paid.is_(False))
            .all()
        )
        for invoice in overdue:
            mailer.send(invoice.customer_email, render_dunning(invoice))
        return len(overdue)
```

The repository is correct and irrelevant. Because the ORM session is importable from the domain,
a use case could take the shortcut, and it did - so every tenant's customers receive dunning
mail, and the mailer is called with addresses the caller was never authorized to see.

```python
# Fixed: the port lives in the domain, the ORM is not importable from here
# domain/ports.py
from typing import Protocol

class InvoicePort(Protocol):
    def list_overdue_for_tenant(self, tenant_id: int, as_of: date, limit: int) -> list[Invoice]: ...

class MailPort(Protocol):
    def send_dunning(self, to: str, invoice: Invoice, timeout_s: float) -> None: ...

# domain/send_dunning_emails.py - no infrastructure import anywhere in this file
class SendDunningEmails:
    def __init__(self, invoices: InvoicePort, mail: MailPort) -> None:
        self._invoices = invoices
        self._mail = mail

    def execute(self, actor: Actor, as_of: date) -> int:
        if not actor.can("invoice:dun"):
            raise PermissionDenied()
        overdue = self._invoices.list_overdue_for_tenant(actor.tenant_id, as_of, limit=500)
        for invoice in overdue:
            self._mail.send_dunning(invoice.contact_email, invoice, timeout_s=5.0)
        return len(overdue)
```

Why it removes the option: the shortcut is not reachable. Nothing in the domain package can name
`session` or `InvoiceRow`, so the only way to read invoices is through a port whose signature
demands a tenant. In Python this is a convention the interpreter will not enforce on its own -
back it with an import-linter contract in CI (`domain` may not import `infrastructure`) so a
reintroduced import fails the build. In C#, Java, or a TypeScript project with enforced project
references, the compiler does this for free.

Residual gap: `limit=500` bounds one run and silently drops the rest. Decide whether the
remainder is processed in the next batch or lost, and record which. A layering lint rule also
does not stop a port implementation from ignoring its `tenant_id` argument - test the adapter.

---

## Port with no timeout or cancellation

`A06:2025` · `API4:2023` · `CWE-770`, `CWE-1088` · ASVS V2

The port has no cancellation parameter, so the adapter has no deadline, and a dependency that
accepts connections without responding pins request threads and their object graphs until the
process dies.

```csharp
// Vulnerable: no token in the port, no timeout in the adapter
public interface ISanctionsScreeningPort
{
    Task<ScreeningResult> ScreenAsync(string fullName);
}

public sealed class HttpSanctionsAdapter : ISanctionsScreeningPort
{
    private static readonly HttpClient Http = new();     // default Timeout, static, shared

    public async Task<ScreeningResult> ScreenAsync(string fullName)
    {
        var response = await Http.GetAsync($"{BaseUrl}/screen?name={Uri.EscapeDataString(fullName)}");
        var body = await response.Content.ReadAsStringAsync();     // unbounded read
        return JsonSerializer.Deserialize<ScreeningResult>(body)!;
    }
}

// Application layer
public async Task<OnboardResult> ExecuteAsync(Actor actor, OnboardCommand cmd)
{
    var screening = await _screening.ScreenAsync(cmd.FullName);    // nothing can cancel this
    // ...
}
```

The client aborting the HTTP request does nothing: no token reaches the outbound call, so the
work continues. Each pending call retains the command, the actor, the buffered response, and the
open connection. A dependency slowdown becomes a memory and connection-pool exhaustion incident,
reachable by anyone who can call the onboarding endpoint.

```csharp
// Fixed: the port declares the token, the adapter owns its budget, the edge sets the deadline
public interface ISanctionsScreeningPort
{
    Task<ScreeningResult> ScreenAsync(string fullName, CancellationToken ct);
}

public sealed class HttpSanctionsAdapter : ISanctionsScreeningPort
{
    private readonly HttpClient _http;      // from IHttpClientFactory
    public HttpSanctionsAdapter(HttpClient http) => _http = http;

    public async Task<ScreeningResult> ScreenAsync(string fullName, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(3));        // this dependency's budget

        using var response = await _http.GetAsync(
            $"screen?name={Uri.EscapeDataString(fullName)}",
            HttpCompletionOption.ResponseHeadersRead, cts.Token);
        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength > 64 * 1024)
            throw new ScreeningProtocolException("response_too_large");

        return await response.Content.ReadFromJsonAsync<ScreeningResult>(cts.Token)
               ?? throw new ScreeningProtocolException("empty_response");
    }
}

// Registration: the client's own ceiling, plus a retry budget with a cap
builder.Services.AddHttpClient<ISanctionsScreeningPort, HttpSanctionsAdapter>(c =>
{
    c.BaseAddress = new Uri("https://screening.example.internal/");
    c.Timeout = TimeSpan.FromSeconds(5);
});

// Application layer: the caller's token flows through, unchanged
public async Task<OnboardResult> ExecuteAsync(
    Actor actor, OnboardCommand cmd, CancellationToken ct)
{
    var screening = await _screening.ScreenAsync(cmd.FullName, ct);
    // ...
}

// Entry point: the request's own cancellation is the root of the chain
[HttpPost("onboarding")]
public Task<IActionResult> Post(OnboardBody body, CancellationToken ct)   // bound by ASP.NET Core
    => Handle(_onboard.ExecuteAsync(ActorFrom(User), body.ToCommand(), ct));
```

Why it removes the option: the token is in the interface, so no implementation can quietly omit
it and no caller can forget to pass one - the compiler asks. The adapter's own `CancelAfter` means
the deadline exists even when the caller passes `CancellationToken.None`, and the linked source
means either side can end the call. `ResponseHeadersRead` plus the length check bounds the
allocation rather than trusting the dependency.

Residual gap: `ContentLength` is a claim, absent on chunked responses. For a hard guarantee, read
through a length-limiting stream instead of trusting the header. Cancellation also does not
guarantee the remote side stopped work - for non-idempotent calls, pair the timeout with an
idempotency key so a retry after a timeout does not double-submit.

---

## Sources

- [references/dependency-rule.md](../references/dependency-rule.md)
- [references/di-lifetimes.md](../references/di-lifetimes.md)
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cwe.mitre.org/>
