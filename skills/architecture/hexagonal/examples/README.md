# Ports and Adapters Examples

Eight before/after pairs. Each one is a real shape: the folders are already named `core` and
`adapters`, the interfaces already exist, and the hole is still open.

Every pair names the boundary that moved, the standard it violates, and what the fix costs.
Blocks labelled Vulnerable contain deliberately unsafe code. Do not copy them.

## Contents

- [The request DTO crosses the port](#the-request-dto-crosses-the-port) — A01, CWE-602, CWE-1220
- [The repository port takes a filter built from query params](#the-repository-port-takes-a-filter-built-from-query-params) — A01, A05, CWE-89, CWE-653
- [Four ports, four implementations, no boundary](#four-ports-four-implementations-no-boundary) — cost only
- [The adapter holds a connection for its own lifetime](#the-adapter-holds-a-connection-for-its-own-lifetime) — CWE-772, CWE-400
- [A singleton adapter captured the first request's tenant](#a-singleton-adapter-captured-the-first-requests-tenant) — A01, CWE-488
- [The in-memory test double reached production](#the-in-memory-test-double-reached-production) — A02, CWE-770
- [A listener is registered per instantiation](#a-listener-is-registered-per-instantiation) — CWE-401, CWE-400
- [The fake adapter skips what the real one enforces](#the-fake-adapter-skips-what-the-real-one-enforces) — A06, A01

---

## The request DTO crosses the port

`A01:2025` · `CWE-602`, `CWE-1220` · ASVS V8

The driving adapter does no mapping. It forwards the parsed body, so the trust boundary is now
inside the use case — and the use case authorizes against fields the client wrote.

```typescript
// Vulnerable
// adapters/inbound/http/dto.ts
export interface ApproveInvoiceDto {
  invoiceId: string;
  tenantId: string; // client-supplied
  role: string;     // client-supplied
}

// adapters/inbound/http/routes.ts
router.post("/invoices/approve", requireAuth, async (req, res) => {
  await invoiceService.approve(req.body as ApproveInvoiceDto);
  res.sendStatus(204);
});

// core/app/invoice-service.ts
async approve(dto: ApproveInvoiceDto): Promise<void> {
  if (dto.role !== "approver") throw new Forbidden();     // checks the caller's own claim
  const invoice = await this.repo.byId(dto.invoiceId, dto.tenantId);
  invoice.approve();
  await this.repo.save(invoice);
}
```

`{"role":"approver","tenantId":"tenant-b"}` approves an invoice in someone else's tenant. The
`requireAuth` middleware proved who the caller is and the use case ignored it. That is `CWE-602`
in its purest form: the server delegated the decision to data the client supplied.

```typescript
// Fixed
// core/ports.ts — the command carries no identity, ever
export interface ApproveInvoiceCommand {
  readonly invoiceId: string;
}

export interface Actor {
  readonly userId: string;
  readonly tenantId: string;
  readonly roles: readonly string[];
  readonly approvalLimitCents: number;
}

export interface InvoiceService {
  approve(actor: Actor, cmd: ApproveInvoiceCommand): Promise<void>;
}

// core/app/invoice-service.ts
async approve(actor: Actor, cmd: ApproveInvoiceCommand): Promise<void> {
  if (!actor.userId || !actor.tenantId) throw new Unauthenticated();
  if (!actor.roles.includes("approver")) throw new NotFound();

  const invoice = await this.repo.findInTenant(actor.tenantId, cmd.invoiceId);
  if (invoice === null) throw new NotFound();

  // Granularity: "approver" is not a licence for any amount (CWE-1220).
  if (invoice.totalCents > actor.approvalLimitCents) throw new Forbidden("approval_limit");
  if (invoice.requestedBy === actor.userId) throw new Forbidden("self_approval");

  invoice.approve(this.clock.now(), actor.userId);
  await this.repo.save(actor.tenantId, invoice);
  this.audit.record(actor, "invoice.approve", invoice.id, "allowed");
}

// adapters/inbound/http/routes.ts — mapping and rejection live here
const Body = z.object({ invoiceId: z.string().uuid() }).strict();

router.post("/invoices/approve", async (req, res) => {
  const session = await verifySession(req);           // throws -> 401
  const parsed = Body.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_request" });

  const actor: Actor = {
    userId: session.userId,
    tenantId: session.tenantId,                       // from the session, not the body
    roles: session.roles,
    approvalLimitCents: session.approvalLimitCents,
  };
  await invoiceService.approve(actor, parsed.data);
  res.sendStatus(204);
});
```

Why it works: the command type has no field an attacker would want to set. `.strict()` rejects
extra keys, so adding `tenantId` to the body is a 400 rather than a silent read. And the queue
consumer written next quarter cannot compile without producing an `Actor`.

Cost: one DTO plus one mapping per adapter per direction. The duplicated field names are the
price of the boundary; reusing the domain type as the wire type is how mass assignment gets in.

---

## The repository port takes a filter built from query params

`A01:2025`, `A05:2025` · `CWE-89`, `CWE-653` · ASVS V8

This is the failure that shows up most often in real reviews. The application layer believes it
applied the tenant scope. It did not, because the scope is a key in a dictionary the client also
controls.

```python
# Vulnerable
# adapters/inbound/http/orders.py
@app.get("/orders")
def list_orders(request):
    filters = dict(request.query_params)          # {"status": "paid", "tenant_id": "9"}
    return [as_json(o) for o in order_service.list(filters)]

# core/app/order_service.py
def list(self, filters: dict) -> list[Order]:
    filters.setdefault("tenant_id", current_tenant())   # client value wins
    return self.orders.find(filters)

# adapters/outbound/postgres/orders.py
def find(self, filters: dict) -> list[Order]:
    where = " AND ".join(f"{k} = '{v}'" for k, v in filters.items())
    rows = self.conn.execute(f"SELECT * FROM orders WHERE {where}")
    return [to_order(r) for r in rows]
```

Three holes from one design decision. `setdefault` means `?tenant_id=9` reads another tenant.
`?tenant_id=9' OR '1'='1` reads all of them. And there is no `LIMIT`, so one request can pull the
table into memory. The port promised a repository and delivered a SQL console — `CWE-653`, the
compartment boundary is gone.

```python
# Fixed
# core/ports.py — tenant is a separate required argument, criteria are typed
from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Protocol

class OrderStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    CANCELLED = "cancelled"

@dataclass(frozen=True)
class OrderCriteria:
    status: OrderStatus | None = None
    placed_after: date | None = None
    limit: int = 50

class OrderRepository(Protocol):
    def find(self, tenant_id: str, criteria: OrderCriteria) -> list[Order]: ...

# core/app/order_service.py
def list(self, actor: Actor, criteria: OrderCriteria) -> list[Order]:
    if not actor.tenant_id:
        raise Unauthenticated()
    return self.orders.find(actor.tenant_id, criteria)

# adapters/outbound/postgres/orders.py
MAX_LIMIT = 200

def find(self, tenant_id: str, criteria: OrderCriteria) -> list[Order]:
    sql = ["SELECT id, status, total_cents, placed_at FROM orders WHERE tenant_id = %(tenant)s"]
    params: dict[str, object] = {"tenant": tenant_id}

    if criteria.status is not None:
        sql.append("AND status = %(status)s")
        params["status"] = criteria.status.value
    if criteria.placed_after is not None:
        sql.append("AND placed_at >= %(after)s")
        params["after"] = criteria.placed_after

    sql.append("ORDER BY placed_at DESC LIMIT %(limit)s")
    params["limit"] = min(max(criteria.limit, 1), MAX_LIMIT)

    with self.pool.connection() as conn, conn.cursor() as cur:
        cur.execute(" ".join(sql), params)
        return [to_order(r) for r in cur.fetchall()]

# adapters/inbound/http/orders.py — query params become criteria through an allowlist
@app.get("/orders")
def list_orders(request):
    actor = actor_from(verify_session(request))
    raw_status = request.query_params.get("status")
    try:
        criteria = OrderCriteria(
            status=OrderStatus(raw_status) if raw_status else None,
            placed_after=date.fromisoformat(request.query_params["after"])
                if "after" in request.query_params else None,
            limit=int(request.query_params.get("limit", 50)),
        )
    except ValueError:
        raise BadRequest("invalid_query")
    return [as_json(o) for o in order_service.list(actor, criteria)]
```

Why it works: `tenant_id` is a positional argument, not a key, so no client input can occupy that
slot and no caller can omit it. The adapter is the only place that writes SQL, and every value
that reaches it is bound. Unknown query params are ignored rather than forwarded, so a new column
does not become a new filter.

Cost: one `WHERE` predicate per query. Make sure the index leads with `tenant_id`, or you have
turned an index seek into a scan the tenant filter no longer helps. See
`skills/architecture/performance/`.

---

## Four ports, four implementations, no boundary

Cost only. No security finding, which is the point.

```java
// Vulnerable to nothing. Just expensive.
core/ports/InvoiceRepositoryPort.java      -> adapters/postgres/InvoiceRepositoryAdapter.java
core/ports/InvoiceMapperPort.java          -> adapters/postgres/InvoiceMapperAdapter.java
core/ports/InvoiceIdGeneratorPort.java     -> adapters/util/UuidInvoiceIdGenerator.java
core/ports/InvoiceNumberFormatterPort.java -> adapters/util/DefaultInvoiceNumberFormatter.java
```

Eight files, four mocks, and a reader who must open two files to follow one call. The mapper and
the formatter are pure functions of their input. The id generator has one implementation that
wraps `UUID.randomUUID()`.

```java
// Fixed: keep the ports that are boundaries, inline the rest.

// core/ports/InvoiceRepository.java
// Port kept deliberately: it pins the tenant predicate into the signature and it is the
// only thing standing between the core and JDBC. Do not inline this. One adapter is fine.
public interface InvoiceRepository {
    Optional<Invoice> findInTenant(String tenantId, String invoiceId);
    void save(String tenantId, Invoice invoice);
}

// core/ports/Clock.java
// Port kept: the wall clock cannot be driven from a test.
public interface Clock { Instant now(); }

// core/domain/InvoiceNumber.java — was a port, now a value object
public record InvoiceNumber(String value) {
    public static InvoiceNumber of(int year, long sequence) {
        return new InvoiceNumber("INV-%d-%06d".formatted(year, sequence));
    }
}
// InvoiceMapperPort and InvoiceIdGeneratorPort are deleted. Mapping lives in the adapter
// that owns the rows; ids come from java.util.UUID at the one call site that needs one.
```

Why it works: the two surviving interfaces each answer "name the second implementation, or name
the security property" — a test double for `Clock`, a tenant predicate for the repository. The
others answered neither, so they were indirection charged to every future reader.

The comment on a single-adapter port is load-bearing. Without it, the next contributor runs the
same audit, finds one implementation, and inlines the only place the tenant scope was enforced.

---

## The adapter holds a connection for its own lifetime

`CWE-772`, `CWE-400`

The port hides the handle, so nothing in the core suggests a resource is open. The adapter's
lifetime and the request's lifetime have quietly stopped matching.

```go
// Vulnerable: one pooled connection acquired at construction, never returned.
func NewOrderRepo(ctx context.Context, pool *pgxpool.Pool) (*OrderRepo, error) {
    conn, err := pool.Acquire(ctx) // checked out here, released never
    if err != nil {
        return nil, err
    }
    return &OrderRepo{conn: conn}, nil
}

func (r *OrderRepo) FindInTenant(ctx context.Context, tenant, id string) (*app.Order, error) {
    row := r.conn.QueryRow(ctx, `SELECT id, status FROM orders WHERE tenant_id=$1 AND id=$2`,
        tenant, id)
    // ...
}
```

Both registration choices fail, differently. Per-request: every request removes one connection
from the pool permanently, so the pool is empty after `max_conns` requests and the service stops.
Singleton: every request in the process serializes on one connection, and a statement that leaves
it in a failed-transaction state makes every later query fail with `current transaction is
aborted` until a restart. Neither shows up in a unit test, and the unit test is the only place a
single-request lifetime is realistic.

```go
// Fixed: the adapter holds the pool. The connection's lifetime is the call's.
type OrderRepo struct{ pool *pgxpool.Pool }

func NewOrderRepo(pool *pgxpool.Pool) *OrderRepo { return &OrderRepo{pool: pool} }

func (r *OrderRepo) FindInTenant(ctx context.Context, tenant, id string) (*app.Order, error) {
    var o app.Order
    err := r.pool.QueryRow(ctx,
        `SELECT id, status, total_cents FROM orders WHERE tenant_id=$1 AND id=$2`,
        tenant, id,
    ).Scan(&o.ID, &o.Status, &o.TotalCents)
    switch {
    case errors.Is(err, pgx.ErrNoRows):
        return nil, nil
    case err != nil:
        return nil, fmt.Errorf("find order: %w", err)
    }
    return &o, nil
}

// A unit of work is a scope, not a field. The transaction cannot outlive the call.
func (r *OrderRepo) InTx(ctx context.Context, fn func(app.OrderRepository) error) error {
    tx, err := r.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx) // no-op after a successful commit
    if err := fn(&txOrderRepo{tx: tx}); err != nil {
        return err
    }
    return tx.Commit(ctx)
}
```

Why it works: acquisition and release are the same lexical scope, enforced by the pool's own API
and a `defer`. The core sees `InTx(ctx, fn)` and cannot hold the transaction past the callback
even by accident.

Composition owns the pool: build it once with `MaxConns`, `MaxConnIdleTime`, and
`MaxConnLifetime` set, and call `pool.Close()` last in the shutdown sequence — after the HTTP
server stopped accepting and in-flight work drained.

---

## A singleton adapter captured the first request's tenant

`A01:2025` · `CWE-488`

A leak in the DI graph, not the heap. The container did what it was asked; what it was asked was
wrong.

```csharp
// Vulnerable
public sealed class ReportExportAdapter : IReportExporter
{
    private readonly ITenantContext _tenant;   // scoped, captured by a singleton

    public ReportExportAdapter(ITenantContext tenant) => _tenant = tenant;

    public Task<Stream> ExportAsync(ReportId id, CancellationToken ct) =>
        _storage.OpenAsync($"{_tenant.TenantId}/{id}.csv", ct);
}

services.AddScoped<ITenantContext, HttpTenantContext>();
services.AddSingleton<IReportExporter, ReportExportAdapter>();   // captive dependency
```

The singleton is constructed once, from whichever scope resolved it first. Its `_tenant` is that
request's tenant, for the lifetime of the process. Every subsequent export reads tenant one's
files. The same shape with a `DbContext` also pins the connection and the change tracker for the
process lifetime, so one request's result set is retained forever — `CWE-772` on top of the
authorization failure.

```csharp
// Fixed: the tenant is an argument, so the adapter holds no request state at all.
public sealed class ReportExportAdapter : IReportExporter
{
    private readonly IObjectStorage _storage;   // process-lifetime, thread-safe client

    public ReportExportAdapter(IObjectStorage storage) => _storage = storage;

    public Task<Stream> ExportAsync(Actor actor, ReportId id, CancellationToken ct) =>
        _storage.OpenAsync($"{actor.TenantId}/{id}.csv", ct);
}

services.AddSingleton<IObjectStorage, S3ObjectStorage>();
services.AddSingleton<IReportExporter, ReportExportAdapter>();   // now legitimately singleton
```

```csharp
// Make the container refuse the mistake instead of trusting review.
var builder = WebApplication.CreateBuilder(args);
builder.Host.UseDefaultServiceProvider(o =>
{
    o.ValidateScopes = true;     // throws on a singleton resolving a scoped service
    o.ValidateOnBuild = true;    // at startup, not on the first export
});
```

```csharp
// A background worker is a singleton driving adapter. It opens a scope per message.
public sealed class ExportWorker(IServiceScopeFactory scopes) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await foreach (var msg in _queue.ReadAllAsync(ct))
        {
            using var scope = scopes.CreateScope();   // disposed per message
            var svc = scope.ServiceProvider.GetRequiredService<IReportService>();
            await svc.ExportAsync(msg.Actor, msg.ReportId, ct);
        }
    }
}
```

Why it works: the adapter's fields are all process-lifetime and immutable, so there is no state
for two requests to share. `ValidateOnBuild` turns the remaining risk into a startup failure.

Limitation: scope validation sees constructor injection. A factory delegate, a static, or a
service locator call inside a method is invisible to it — grep adapter constructors and method
bodies for actor, tenant, session, connection, and cursor types by hand.

---

## The in-memory test double reached production

`A02:2025` · `CWE-770`, `CWE-400`

Written as a fake, wired into the real container by a fallback that looks defensive.

```typescript
// Vulnerable
// adapters/memory/idempotency-store.ts
export class InMemoryIdempotencyStore implements IdempotencyStore {
  private readonly seen = new Map<string, Date>();          // no cap, no TTL, no eviction

  async claim(key: string): Promise<boolean> {
    if (this.seen.has(key)) return false;
    this.seen.set(key, new Date());
    return true;
  }
}

// composition/container.ts
const idempotency: IdempotencyStore = process.env.REDIS_URL
  ? new RedisIdempotencyStore(process.env.REDIS_URL)
  : new InMemoryIdempotencyStore();                          // silent fallback
```

Two failures compound. The map is keyed by a client-supplied `Idempotency-Key` header, so its
growth rate is attacker-controlled and the process dies by heap exhaustion — `CWE-770`. And the
store is per-process, so with three replicas the same payment request retried against a different
replica is charged twice. A missing environment variable turned a correctness guarantee off
without a log line: `A02:2025`, fail-open configuration.

```typescript
// Fixed
// composition/container.ts — required config fails at boot
function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
}

const idempotency: IdempotencyStore = new RedisIdempotencyStore(requireEnv("REDIS_URL"));
```

```typescript
// adapters/memory/idempotency-store.ts — bounded even in tests, and labelled
/**
 * Test double. Not exported from the production entry point; see package.json "exports".
 * Bounded anyway: an unbounded map in a test suite hides the growth it would cause in prod.
 */
export class InMemoryIdempotencyStore implements IdempotencyStore {
  private readonly seen = new Map<string, number>();

  constructor(private readonly maxEntries = 10_000, private readonly ttlMs = 60_000) {}

  async claim(key: string): Promise<boolean> {
    const now = Date.now();
    const at = this.seen.get(key);
    if (at !== undefined && now - at < this.ttlMs) return false;

    if (this.seen.size >= this.maxEntries) {
      const oldest = this.seen.keys().next();          // Map preserves insertion order
      if (!oldest.done) this.seen.delete(oldest.value);
    }
    this.seen.set(key, now);
    return true;
  }
}
```

Why it works: the production path has one implementation and no fallback, so the failure mode of
a missing variable is a container that will not start rather than a service that quietly loses a
guarantee. Keeping the double bounded means a load test against the fake shows the same shape of
pressure as the real thing.

The general rule: a `Map` with no maximum is not a cache, it is a queue that never drains. If a
double is fast enough to tempt someone into production use, bound it and gate it at the module
boundary, because the comment will not stop them.

---

## A listener is registered per instantiation

`CWE-401`, `CWE-400`

The subscription is the retained reference. Every listener holds the adapter, and the adapter
holds an HTTP client, a credential, and a reference back into the core.

```typescript
// Vulnerable
export class NotificationAdapter implements Notifier {
  constructor(private readonly bus: EventEmitter, private readonly secrets: SecretsPort) {
    bus.on("config.reload", () => this.refreshCredential());   // one listener per instance
  }
  // ...
}

// adapters/inbound/http/routes.ts
router.post("/orders/:id/notify", async (req, res) => {
  const notifier = new NotificationAdapter(bus, secrets);      // a new listener per request
  await orderService.notify(actorFrom(req), { orderId: req.params.id }, notifier);
  res.sendStatus(204);
});
```

Listeners accumulate for the life of the process. Two consequences: heap grows linearly with
request count and nothing is collectable while the emitter is alive (`CWE-401`), and one
`config.reload` event fans out into N credential fetches against the secret manager, which is a
self-inflicted thundering herd (`CWE-400`). Node's `MaxListenersExceededWarning` is the only hint,
and it goes to stderr where nobody reads it.

```typescript
// Fixed: constructed once in composition, teardown owned by whoever constructed it.
export class NotificationAdapter implements Notifier {
  #stop = new AbortController();

  private constructor(
    private readonly bus: EventEmitter,
    private readonly secrets: SecretsPort,
    private credential: string,
  ) {}

  static async start(bus: EventEmitter, secrets: SecretsPort): Promise<NotificationAdapter> {
    const self = new NotificationAdapter(bus, secrets, await secrets.get("notifier"));
    bus.on("config.reload", self.#onReload, { signal: self.#stop.signal });
    return self;
  }

  #onReload = async (): Promise<void> => {
    this.credential = await this.secrets.get("notifier");
  };

  async stop(): Promise<void> {
    this.#stop.abort();                 // removes the listener
    await this.client.close();
  }
}

// composition/root.ts
const notifier = await NotificationAdapter.start(bus, secrets);
bus.setMaxListeners(20);                // a regression becomes a warning at a known threshold

process.once("SIGTERM", async () => {
  await httpServer.close();             // stop accepting
  await notifier.stop();                // unregister, close the client
  await pool.end();                     // release the pool last
  process.exit(0);
});
```

Why it works: registration and removal belong to the same object, and the object is created once
where the process lifetime is decided. The `AbortSignal` ties removal to a single call, so there
is no way to add the listener and forget the matching `off`.

Route handlers receive the adapter as a parameter or from the container — they never construct
one. Any `new SomethingAdapter(...)` inside a request handler is worth a second look; the handler
is not where lifetimes are decided.

---

## The fake adapter skips what the real one enforces

`A06:2025`, `A01:2025`

The suite is green and it proves nothing. This is the trap in the pattern's main payoff.

```go
// Vulnerable: the fake ignores the arguments that carry the security property.
type fakeOrders struct{ byID map[string]*app.Order }

func (f *fakeOrders) FindInTenant(_ context.Context, _, id string) (*app.Order, error) {
    return f.byID[id], nil          // tenant discarded
}
```

```go
// adapters/postgres/orders.go — nobody noticed the missing predicate
func (r *OrderRepo) FindInTenant(ctx context.Context, tenant, id string) (*app.Order, error) {
    row := r.pool.QueryRow(ctx, `SELECT id, status FROM orders WHERE id = $1`, id) // no tenant
    // ...
}
```

The abuse test passes, because the use case also compares `order.TenantID` to the actor's tenant
after loading. So the boundary looks tested. It is not: the fake never exercised the predicate,
the real adapter never had one, and every other caller of `FindInTenant` — a list endpoint, an
export job, an audit log line that prints the order number before the check — reads across
tenants. The redundant in-core check is what hid it.

```go
// Fixed: one contract suite, two implementations, same assertions.
// core/ports/contract/orders.go
package contract

func RunOrderRepositoryContract(
    t *testing.T,
    newRepo func(t *testing.T) app.OrderRepository,
) {
    t.Run("returns an order in the tenant", func(t *testing.T) {
        repo := newRepo(t)
        seed(t, repo, "tenant-a", &app.Order{ID: "ord-1", TenantID: "tenant-a"})

        got, err := repo.FindInTenant(context.Background(), "tenant-a", "ord-1")
        if err != nil || got == nil {
            t.Fatalf("want order, got %v err %v", got, err)
        }
    })

    t.Run("returns nothing for another tenant's order", func(t *testing.T) {
        repo := newRepo(t)
        seed(t, repo, "tenant-a", &app.Order{ID: "ord-1", TenantID: "tenant-a"})

        got, err := repo.FindInTenant(context.Background(), "tenant-b", "ord-1")
        if err != nil {
            t.Fatalf("unexpected error: %v", err)
        }
        if got != nil {
            t.Fatal("cross-tenant read: the tenant predicate is missing")
        }
    })

    t.Run("clamps the page size", func(t *testing.T) {
        repo := newRepo(t)
        got, err := repo.Find(context.Background(), "tenant-a", app.OrderCriteria{Limit: 1_000_000})
        if err != nil {
            t.Fatalf("unexpected error: %v", err)
        }
        if len(got) > 200 {
            t.Fatalf("limit not clamped: %d rows", len(got))
        }
    })
}
```

```go
// adapters/memory/orders_test.go
func TestInMemoryOrderRepo_Contract(t *testing.T) {
    contract.RunOrderRepositoryContract(t, func(t *testing.T) app.OrderRepository {
        return memory.NewOrderRepo()
    })
}

// adapters/postgres/orders_test.go
func TestPostgresOrderRepo_Contract(t *testing.T) {
    dsn := os.Getenv("TEST_POSTGRES_DSN")
    if dsn == "" {
        t.Skip("TEST_POSTGRES_DSN not set: adapter behaviour is UNVERIFIED in this run")
    }
    contract.RunOrderRepositoryContract(t, func(t *testing.T) app.OrderRepository {
        return postgres.NewOrderRepo(freshSchema(t, dsn))
    })
}
```

```go
// adapters/memory/orders.go — the fake now has to enforce the same thing
func (r *OrderRepo) FindInTenant(_ context.Context, tenant, id string) (*app.Order, error) {
    o := r.byID[id]
    if o == nil || o.TenantID != tenant {
        return nil, nil
    }
    return o, nil
}
```

Why it works: the assertions live in one place, so the fake cannot be more permissive than the
real adapter without failing the same test. The cross-tenant case is written as a repository
contract, not as a use-case test, so it holds for every caller of the port rather than for the
one path that happened to have a second check.

The `t.Skip` is deliberate and it must be loud. A skipped contract run means the real adapter is
unverified in that pipeline — report it that way rather than counting the fake's pass. Make the
DSN required in CI and optional only for local runs.

Keep the redundant in-core check. Defence in depth is fine; relying on it to cover a missing
predicate is not.

## Sources

- <https://alistair.cockburn.us/hexagonal-architecture/>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cwe.mitre.org/>
