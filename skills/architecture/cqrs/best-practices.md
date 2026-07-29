# CQRS Best Practices

Each pattern names the security implication and the runtime cost. A pattern with no cost note is
incomplete - every indirection here buys something and charges for it.

## Start at the cheap version

Separate methods, separate DTOs, one database, one transaction. No broker, no projector, no
eventual consistency.

```csharp
// Command side: intent-named, returns an id, authorization inside the aggregate
public sealed record ApproveInvoice(Guid CommandId, Guid TenantId, Guid InvoiceId, Guid ActorId);

public sealed class ApproveInvoiceHandler
{
    private readonly IInvoiceRepository _invoices;
    private readonly IUnitOfWork _uow;

    public async Task<Guid> Handle(ApproveInvoice cmd, CancellationToken ct)
    {
        // Tenant is part of the load, not a check afterwards.
        var invoice = await _invoices.Load(cmd.TenantId, cmd.InvoiceId, ct)
            ?? throw new NotFoundException();

        invoice.Approve(cmd.ActorId);        // throws if the actor may not approve
        await _uow.SaveChanges(ct);
        return invoice.Id;
    }
}

// Query side: explicit DTO, tenant in the signature, no domain object escapes
public sealed record InvoiceListRow(Guid Id, string Number, decimal Total, string Status);

public sealed class InvoiceListQuery
{
    private readonly IDbConnection _db;

    public Task<IReadOnlyList<InvoiceListRow>> Handle(Guid tenantId, int limit, CancellationToken ct)
        => _db.QueryAsync<InvoiceListRow>(
            "SELECT id, number, total, status FROM invoice_list_view " +
            "WHERE tenant_id = @tenantId ORDER BY created_at DESC LIMIT @limit",
            new { tenantId, limit = Math.Clamp(limit, 1, 200) }, ct);
}
```

Security: the aggregate is the only place the approval rule lives, and the query returns a
declared shape rather than the entity. No `password_hash` or `internal_note` can appear because
no column was selected. `API3:2023`.

Cost: one extra type per read shape. That is it. No lag, no replay, no broker.

Do not move past this until you can state the measured read/write asymmetry that justifies it.

## Commands

A command names a business intent and returns as little as possible.

```typescript
// Vulnerable as a design: this is a table update wearing a command's name,
// and it returns the whole entity so callers start reading from the write side.
type UpdateInvoice = { id: string; fields: Record<string, unknown> };
async function updateInvoice(cmd: UpdateInvoice): Promise<Invoice> {
  return db.invoice.update({ where: { id: cmd.id }, data: cmd.fields });
}
```

`fields` is mass assignment: `status`, `tenantId`, and `approvedBy` are all settable by the
caller. `API3:2023`, `CWE-915`. Returning the entity means the read shape is now the write
shape, and every field added to the table becomes an API field.

```typescript
// Fixed: intent named, payload closed, actor derived server-side, id returned
const ApproveInvoice = z.object({
  commandId: z.string().uuid(),
  invoiceId: z.string().uuid(),
}).strict();

async function approveInvoice(raw: unknown, actor: Actor): Promise<{ invoiceId: string }> {
  const cmd = ApproveInvoice.parse(raw);
  return withTransaction(async (tx) => {
    const claimed = await claimCommand(tx, cmd.commandId, actor.tenantId);
    if (!claimed) return { invoiceId: cmd.invoiceId };   // already applied

    const invoice = await loadInvoice(tx, actor.tenantId, cmd.invoiceId);
    if (!invoice) throw new NotFoundError();
    invoice.approve(actor);                              // rules live here
    await saveInvoice(tx, invoice);
    return { invoiceId: invoice.id };
  });
}
```

Security: `.strict()` closes the payload. `actor.tenantId` comes from the session, never the
body. The rule is inside `invoice.approve`, so there is no path that writes the status without
passing it.

Cost: one row in a command-dedup table per command, and that table needs a retention policy or
it becomes an unbounded store. Keep it as long as your retry window plus a margin, then delete
by date with an index on the date column.

### Idempotency

A command handler behind a queue will receive duplicates. At-least-once delivery is the norm;
brokers redeliver on ack timeout, and clients retry on connection reset.

Dedupe on a command ID inside the same transaction as the state change:

```sql
-- The unique constraint is the control. A duplicate insert fails, so the
-- transaction rolls back and the state change cannot be applied twice.
CREATE TABLE applied_command (
    tenant_id   uuid        NOT NULL,
    command_id  uuid        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, command_id)
);
CREATE INDEX applied_command_applied_at_idx ON applied_command (applied_at);
```

```csharp
// Fixed: claim and apply share one transaction
await using var tx = await _db.BeginTransactionAsync(ct);
try
{
    await _db.ExecuteAsync(
        "INSERT INTO applied_command (tenant_id, command_id) VALUES (@t, @c)",
        new { t = cmd.TenantId, c = cmd.CommandId }, tx);
}
catch (PostgresException e) when (e.SqlState == "23505")   // unique_violation
{
    await tx.RollbackAsync(ct);
    return;                                                 // duplicate, already applied
}

await ApplyStateChange(cmd, tx, ct);
await tx.CommitAsync(ct);
```

Why this removes the option: the claim and the effect commit together. A check-then-act version
(`SELECT` then `INSERT`) has a window where two concurrent deliveries both see nothing and both
apply. `CWE-367`.

For HTTP-level idempotency keys on the edge - header handling, response replay, key reuse with a
different body - use `skills/core/api-security/` rather than reimplementing it here. The two are
different layers: the API key protects the client's retry, the command ID protects the broker's
redelivery.

## Projections carry authorization, not just display data

This is the central pattern in this skill.

```sql
-- Vulnerable: the projection stores what the dashboard renders.
-- Tenant is not here, so scoping is a thing every consumer must remember.
CREATE TABLE invoice_list_view (
    invoice_id  uuid PRIMARY KEY,
    number      text NOT NULL,
    total       numeric(12,2) NOT NULL,
    status      text NOT NULL,
    created_at  timestamptz NOT NULL
);
```

One `SELECT * FROM invoice_list_view ORDER BY created_at DESC LIMIT 50` in an admin dashboard,
or a support tool, or an export job, returns rows across every tenant. It looks correct. It
returns data. Nothing errors. `A01:2025`, `API1:2023`, `CWE-1220`.

```sql
-- Fixed: tenant is part of the identity of a row, and of every index
CREATE TABLE invoice_list_view (
    tenant_id   uuid NOT NULL,
    invoice_id  uuid NOT NULL,
    owner_id    uuid NOT NULL,
    number      text NOT NULL,
    total       numeric(12,2) NOT NULL,
    status      text NOT NULL,
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, invoice_id)
);

CREATE INDEX invoice_list_view_tenant_created_idx
    ON invoice_list_view (tenant_id, created_at DESC);

-- Second layer: the database refuses an unscoped read even if the query forgets.
ALTER TABLE invoice_list_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_list_view FORCE ROW LEVEL SECURITY;

CREATE POLICY invoice_list_view_tenant ON invoice_list_view
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

Then make the unscoped query unrepresentable in code:

```csharp
// The repository has no method that omits the tenant. There is nothing to forget.
public interface IInvoiceListReader
{
    Task<IReadOnlyList<InvoiceListRow>> Recent(TenantId tenant, int limit, CancellationToken ct);
    Task<InvoiceListRow?> ById(TenantId tenant, Guid invoiceId, CancellationToken ct);
}
```

Why this works rather than relying on discipline: three independent layers. `TenantId` is a
required parameter so an unscoped call does not compile. The composite primary key means a
projector that forgets the tenant collides on insert instead of silently overwriting another
tenant's row. Row-level security means a raw `psql` query or a new ORM path still cannot read
across tenants.

Cost: the composite key widens every index. On a 50-million-row projection a `uuid` prefix on
each index is real storage and slightly worse cache locality. Measure it; do not skip it. RLS
adds a predicate to every plan - usually negligible with the matching index, occasionally
enough to change a plan choice. Check `EXPLAIN` after enabling it.

Also include `owner_id` even when the current screens do not display it. The next screen will
need "only mine", and adding a column to a large projection means a backfill or a replay.

## Read models are shaped per use case

```typescript
// Vulnerable: one denormalised view joined from everything, filtered in the client
const row = await db.$queryRaw`
  SELECT i.*, c.*, u.*
  FROM invoice i
  JOIN customer c ON c.id = i.customer_id
  JOIN app_user u ON u.id = i.created_by
  WHERE i.tenant_id = ${tenantId} AND i.id = ${invoiceId}`;
res.json(row);
```

`SELECT *` across three tables ships `c.internal_credit_note`, `u.password_hash`,
`u.mfa_secret`, and `i.fraud_score` to the browser. This is the most common way internal fields
reach a response. `API3:2023`, `CWE-213`.

```typescript
// Fixed: the projection is the contract. Columns are chosen once, at build time.
type InvoiceDetail = {
  invoiceId: string;
  number: string;
  total: string;
  status: string;
  customerName: string;
  createdByDisplayName: string;
};

const detail = await db.invoiceDetailView.findUnique({
  where: { tenantId_invoiceId: { tenantId: actor.tenantId, invoiceId } },
  select: {
    invoiceId: true, number: true, total: true, status: true,
    customerName: true, createdByDisplayName: true,
  },
});
```

Security: adding `fraud_score` to the invoice table cannot leak, because the projection does not
project it and the response type does not contain it. The alternative - a view plus a serializer
that strips fields - fails the first time somebody adds a column and forgets the strip list.

Cost: one projection per read shape means write amplification. Five projections mean five
upserts per event. That is the trade: query cost moves to write time. Budget it, and do not
build a projection for a screen that runs twice a month - run the join for that one.

## Eventual consistency is a hazard

Two failures, both real.

### Authorization from a stale projection

```csharp
// Vulnerable: permissions were revoked 200 ms ago. The projection has not caught up.
public async Task<IActionResult> Export(Guid reportId, CancellationToken ct)
{
    var perms = await _permissionReadModel.ForActor(_actor.Id, ct);   // eventually consistent
    if (!perms.Contains("report:export")) return Forbid();
    return File(await _reports.Render(_actor.TenantId, reportId, ct), "text/csv");
}
```

The revoked user exports for as long as the projector lags. Under load that lag is not
milliseconds; it is however long the queue is.

```csharp
// Fixed: the decision reads the authoritative store
public async Task<IActionResult> Export(Guid reportId, CancellationToken ct)
{
    var granted = await _authz.HasPermission(_actor.Id, "report:export", ct); // write store
    if (!granted) return Forbid();
    return File(await _reports.Render(_actor.TenantId, reportId, ct), "text/csv");
}
```

State it plainly: authorization decisions must not read from an eventually consistent
projection. If performance forces a cache in front of the authoritative store, that is a cache
with a TTL you chose and can state, not an unbounded projection lag you cannot. `A01:2025`,
`A06:2025`.

### Check-then-act against a projection

```typescript
// Vulnerable: the seat count comes from a projection, the write happens elsewhere
const remaining = await readModel.seatsRemaining(eventId);   // may be stale
if (remaining <= 0) throw new SoldOutError();
await commandBus.send({ type: "ReserveSeat", eventId, actorId });
```

Two buyers both read `1`. Both commands succeed. You oversold.

```typescript
// Fixed: the invariant is enforced where the state is authoritative
await withTransaction(async (tx) => {
  const updated = await tx.execute(
    `UPDATE event_capacity SET seats_taken = seats_taken + 1
     WHERE event_id = $1 AND seats_taken < seats_total`,
    [eventId],
  );
  if (updated.rowCount === 0) throw new SoldOutError();
  await insertReservation(tx, eventId, actorId);
});
```

The read model is still useful - it renders "3 seats left" on the page. It just cannot be the
gate. Use the projection to inform the UI and the authoritative store to decide.

### Reading your own write

A user who just changed something and sees the old value files a bug. Options, in order of
preference:

1. Return enough from the command to render the result optimistically. The command knows what it
   did.
2. Route that user's reads to the write store for a short window after their command.
3. Have the command return a version, and let the client poll the read model until it reports
   that version or later.

Do not fix it by making the projector synchronous - that reintroduces the coupling the split was
meant to remove, and it means a projector failure fails the command.

## Projector resource lifetime

The projector is a long-lived process consuming an unbounded stream. Everything it retains is
retained forever.

```typescript
// Vulnerable: an in-memory map keyed by entity id, one entry per entity ever seen.
// This is L1 in skills/architecture/performance - unbounded cache. CWE-401.
const totals = new Map<string, number>();

export async function onOrderLine(ev: OrderLineAdded) {
  const current = totals.get(ev.orderId) ?? 0;
  totals.set(ev.orderId, current + ev.amount);
  await db.orderTotalView.upsert({
    where: { tenantId_orderId: { tenantId: ev.tenantId, orderId: ev.orderId } },
    create: { tenantId: ev.tenantId, orderId: ev.orderId, total: totals.get(ev.orderId)! },
    update: { total: totals.get(ev.orderId)! },
  });
}
```

Every order the system has ever processed stays in `totals`. RSS grows with the business, not
with concurrency. It survives every deploy-length window and dies at the container limit.

```typescript
// Fixed: no accumulated state. The database holds the running total.
export async function onOrderLine(ev: OrderLineAdded) {
  await db.$executeRaw`
    INSERT INTO order_total_view (tenant_id, order_id, total, last_event_seq)
    VALUES (${ev.tenantId}, ${ev.orderId}, ${ev.amount}, ${ev.seq})
    ON CONFLICT (tenant_id, order_id) DO UPDATE
      SET total          = order_total_view.total + EXCLUDED.total,
          last_event_seq = EXCLUDED.last_event_seq
    WHERE order_total_view.last_event_seq < EXCLUDED.last_event_seq`;
}
```

The `WHERE last_event_seq < EXCLUDED.last_event_seq` clause is what makes redelivery safe: a
replayed event is ignored rather than double-counted. Idempotency and boundedness in one
statement.

If in-memory state is genuinely needed for throughput, bound it explicitly:

```typescript
// Bounded: an LRU with a size cap and a TTL, plus a documented basis for the number.
// 20 000 entries x ~120 bytes ≈ 2.4 MB, against a 512 MB container budget.
const hot = new LRUCache<string, number>({ max: 20_000, ttl: 5 * 60_000 });
```

A cache miss then reads from the projection. Correctness does not depend on the cache being
present - that is the test for whether a cache is safe to add.

Detail on bounds, backpressure, and diagnosis belongs to
`skills/architecture/performance/`. Do not duplicate it; link to it.

### Queue depth between command side and projector

An unbounded in-memory channel between the command handler and the projector converts a slow
projector into a memory leak, and converts a burst into an OOM kill. `API4:2023`, `CWE-770`.

```csharp
// Fixed: bounded channel, explicit full behaviour, lag observable
var channel = Channel.CreateBounded<ProjectionEvent>(new BoundedChannelOptions(10_000)
{
    FullMode = BoundedChannelFullMode.Wait,   // backpressure onto the producer
    SingleReader = true,
});
```

Choose block, drop, or reject and write down which. Blocking means the command side slows when
the projector does - usually correct, and it is a decision, not an accident. Emit projection lag
as a metric: `now() - max(event_time)` per projection. Lag is the number that tells you whether
a stale read is a millisecond or an hour.

### Replay cost

Rebuilding a projection in production is not a background task. It reads the entire event
history and writes the entire projection.

- Build into a new table, then swap. Never `TRUNCATE` the live projection and refill it - that
  is a read outage measured in however long the replay takes.
- Version the projection name (`invoice_list_view_v3`) and switch readers at the repository, so
  rollback is a config change.
- Throttle the replay. An unthrottled replay saturates the write store and takes production
  latency with it.
- Measure first: rows × per-row cost. If the answer is nine hours, that is a planned operation
  with a runbook, not a deploy step.
- Replay is not free of side effects unless you made it so. A projector that sends an email is
  not a projector.

## Dual writes and the outbox

```csharp
// Vulnerable: two systems, no transaction. A crash between them loses the event.
await _db.SaveChangesAsync(ct);            // committed
await _broker.PublishAsync(evt, ct);       // process dies here
```

This does not fail loudly. The write succeeded, the projection never updates, and the read model
is quietly wrong for that row forever. Users report missing data weeks later. `A08:2025`
(software or data integrity failures).

Reversing the order is worse: publish then commit means consumers see events for state that was
rolled back.

```csharp
// Fixed: the event is a row in the same transaction as the state change
await using var tx = await _db.BeginTransactionAsync(ct);
_db.Invoices.Update(invoice);
_db.Outbox.Add(new OutboxMessage
{
    Id          = Guid.NewGuid(),
    TenantId    = invoice.TenantId,
    Type        = nameof(InvoiceApproved),
    Payload     = JsonSerializer.Serialize(new InvoiceApproved(invoice.Id, invoice.TenantId)),
    OccurredAt  = DateTimeOffset.UtcNow,
});
await _db.SaveChangesAsync(ct);
await tx.CommitAsync(ct);
```

```sql
-- The relay claims a batch without two workers taking the same rows.
UPDATE outbox_message
SET    claimed_at = now(), claimed_by = $1
WHERE  id IN (
    SELECT id FROM outbox_message
    WHERE  published_at IS NULL
      AND (claimed_at IS NULL OR claimed_at < now() - interval '1 minute')
    ORDER BY occurred_at
    FOR UPDATE SKIP LOCKED
    LIMIT 100
)
RETURNING id, type, payload;
```

Why this works: there is one transaction, so there is no window. Either both the state and the
event exist, or neither does.

What it does not fix: the relay can publish and then crash before marking the row published, so
consumers get duplicates. At-least-once is the guarantee, which is why every projector needs the
sequence guard shown above. Say this rather than implying exactly-once.

Cost: one table that grows at the rate of your writes. Delete published rows on a schedule with
an index on `published_at`, or the outbox becomes the largest table in the database. Ordering is
per-aggregate at best - a single relay with `ORDER BY occurred_at` gives global order and a
throughput ceiling; partitioning by aggregate gives throughput and only per-aggregate order.
Pick one deliberately.

## Event sourcing: optional, and separate

CQRS does not require event sourcing. Most CQRS should not use it. If you introduce it, these are
the parts that bite.

### Replay changes behaviour

Rebuilding state from events runs today's code over yesterday's events. If a rule changed, the
rebuilt state differs from the state that was originally computed. That is a correctness problem
and sometimes an audit problem.

- Handlers must be pure functions of the event and current state. No clock, no random, no HTTP.
- Store what was decided, not what should be recomputed. If a tax rate applied, the event carries
  the rate. Do not look it up during replay.
- Snapshot at intervals so replay does not read from the beginning of time. A snapshot is a
  cache; it must be reproducible from the events, and it must be versioned with the handler code.

### PII in an immutable log

An append-only store and a legal erasure obligation are in direct conflict. GDPR Article 17
gives a data subject the right to erasure without undue delay. "Our event store is immutable" is
not an exemption.

The usual answer is crypto-shredding: keep personal data encrypted with a per-subject key held
outside the event store, and delete the key on an erasure request.

```csharp
// Events carry ciphertext plus the key id. Deleting the key makes the payload unreadable.
public sealed record CustomerRegistered(
    Guid   CustomerId,
    Guid   TenantId,
    string SubjectKeyId,      // pointer into the key store
    byte[] EncryptedProfile,  // AES-GCM ciphertext, nonce prefixed
    DateTimeOffset OccurredAt);
```

Honest limitations, all of which must be stated to whoever signs off on the design:

- Whether crypto-shredding satisfies erasure in a given jurisdiction is a legal question, not an
  engineering one. Get it reviewed.
- Backups still hold the key until the backup retention window expires. Say what that window is.
- Replay after shredding must tolerate an undecryptable payload. The handler needs a "subject
  erased" path, not an exception.
- Structural data - that customer `X` existed, and when - usually remains, because the sequence
  is the source of truth. Decide whether that residue is acceptable.
- A projection built before erasure may still hold plaintext. Erasure must rebuild or purge
  affected projections too.

Do not put personal data in an event you cannot re-key. `A04:2025`, ASVS V11, V14.

### Event schema evolution

Stored events outlive the code that wrote them. Once an event is persisted, its schema is a
published contract with no version negotiation.

- Only additive changes are safe: new optional fields with a defined default.
- Never reuse a field name with a different meaning. That silently corrupts old events.
- To change shape, write a new event type and an upcaster from the old one. Keep the upcaster
  forever, or until you rewrite the store.
- Serialize with an explicit contract, not the language's default reflection-based serializer.
  A class rename must not change how existing events deserialize.

```java
// Java: version the type, upcast on read, keep both paths
public sealed interface CustomerEvent {
    record CustomerRegisteredV1(UUID customerId, String email) implements CustomerEvent {}
    record CustomerRegisteredV2(UUID customerId, UUID tenantId, String email) implements CustomerEvent {}
}

static CustomerEvent upcast(CustomerEvent e, UUID legacyTenantId) {
    if (e instanceof CustomerEvent.CustomerRegisteredV1 v1) {
        // V1 predates multi-tenancy. The tenant is derived from the stream, not guessed.
        return new CustomerEvent.CustomerRegisteredV2(v1.customerId(), legacyTenantId, v1.email());
    }
    return e;
}
```

Note what that upcaster shows: a V1 event has no tenant, so a projection built from mixed
versions has rows whose tenant came from a migration decision. Get that decision right once,
because it is baked into the projection afterwards.

## Sources

- <https://learn.microsoft.com/en-us/azure/architecture/patterns/cqrs>
- <https://martinfowler.com/bliki/CQRS.html>
- <https://microservices.io/patterns/data/transactional-outbox.html>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cwe.mitre.org/data/definitions/1220.html>
