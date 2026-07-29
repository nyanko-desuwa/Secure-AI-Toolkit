# CQRS Examples

Eight before/after pairs. Each names the failure in one sentence, shows the code, shows the fix,
says why the fix removes the option rather than relying on discipline, and names the residual gap.

Categories are OWASP Top 10 2025 and API Security Top 10 2023. A CWE appears only where one
genuinely fits. Several of these are correctness defects with no CWE, and that is stated instead
of forcing a mapping.

The language is incidental. The mistake is not.

## Contents

- [Read model without the tenant filter](#read-model-without-the-tenant-filter) - A01, API1, CWE-1220
- [Denormalised view leaking internal fields](#denormalised-view-leaking-internal-fields) - API3, CWE-213
- [Command validated against a stale read model](#command-validated-against-a-stale-read-model) - A06, CWE-367
- [Projector that double-applies on redelivery](#projector-that-double-applies-on-redelivery) - A08, CWE-837
- [Dedupe set held in memory, unbounded](#dedupe-set-held-in-memory-unbounded) - API4, CWE-770
- [Dual write with no outbox](#dual-write-with-no-outbox) - A08, no CWE
- [Stale read after write, "fixed" by reading the write store](#stale-read-after-write-fixed-by-reading-the-write-store) - no CWE
- [Event schema change that breaks replay](#event-schema-change-that-breaks-replay) - no CWE
- [When not to use CQRS](#when-not-to-use-cqrs)

---

## Read model without the tenant filter

`A01:2025` · `API1:2023` · `CWE-1220` · ASVS V8

The command side scoped every load by tenant. The projection did not carry the tenant, so the
query side became the authorization hole.

The write path, which is correct:

```typescript
// src/commands/approve-invoice.ts - tenant is part of the load, not a check afterwards
const invoice = await loadInvoice(tx, actor.tenantId, cmd.invoiceId);
if (!invoice) throw new NotFoundError();
invoice.approve(actor);
```

The read path, which is not:

```sql
-- Vulnerable: the projection stores what the dashboard renders. No tenant column.
CREATE TABLE invoice_list_view (
    invoice_id  uuid PRIMARY KEY,
    number      text NOT NULL,
    total       numeric(12,2) NOT NULL,
    status      text NOT NULL,
    created_at  timestamptz NOT NULL
);
```

```typescript
// Vulnerable: src/read-models/invoice-list.ts
export async function recentInvoices(limit: number): Promise<InvoiceListRow[]> {
  return sql<InvoiceListRow[]>`
    SELECT invoice_id, number, total, status
    FROM   invoice_list_view
    ORDER  BY created_at DESC
    LIMIT  ${limit}`;
}
```

Nothing errors. The endpoint returns rows, sorted, paginated, and rendered correctly - from every
tenant in the system. This survives review because the reviewer is looking at the command side,
where the rule lives.

```sql
-- Fixed: tenant is part of the identity of a row, and of the index that serves the query
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

ALTER TABLE invoice_list_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_list_view FORCE ROW LEVEL SECURITY;

CREATE POLICY invoice_list_view_tenant ON invoice_list_view
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

```typescript
// Fixed: an unscoped call does not type-check, and the page size is clamped server-side
declare const brand: unique symbol;
export type TenantId = string & { readonly [brand]: "TenantId" };

export async function recentInvoices(
  tenant: TenantId,
  limit: number,
): Promise<InvoiceListRow[]> {
  const capped = Math.min(Math.max(Math.trunc(limit) || 25, 1), 200);
  return sql<InvoiceListRow[]>`
    SELECT invoice_id, number, total, status
    FROM   invoice_list_view
    WHERE  tenant_id = ${tenant}
    ORDER  BY created_at DESC
    LIMIT  ${capped}`;
}
```

Why this removes the option: three independent layers, none of which is a habit. `TenantId` is a
required parameter of a branded type, so the unscoped call fails compilation rather than review.
The composite primary key means a projector that forgets the tenant collides on insert instead of
overwriting another tenant's row. Row-level security means a new ORM path, a migration script, or
a `psql` session still cannot read across tenants.

Residual gap: RLS depends on `app.tenant_id` being set on the connection. With a pooled
connection that is reused without `RESET`, a query can inherit the previous request's tenant.
Set it inside the same transaction as the query (`SET LOCAL`), and make the connection-acquire
helper the only place that does it.

---

## Denormalised view leaking internal fields

`API3:2023` · `CWE-213` · ASVS V4, V14

Building a read model by joining everything ships the columns nobody meant to publish.

```typescript
// Vulnerable: src/read-models/invoice-detail.ts
const rows = await db.$queryRaw`
  SELECT i.*, c.*, u.*
  FROM   invoice i
  JOIN   customer c ON c.id = i.customer_id
  JOIN   app_user u ON u.id = i.created_by
  WHERE  i.tenant_id = ${actor.tenantId} AND i.id = ${invoiceId}`;
res.json(rows[0]);
```

Tenant scoping is present, so this passes an A01 review. It still ships
`u.password_hash`, `u.mfa_secret`, `c.internal_credit_note`, and `i.fraud_score` to the browser.
Adding a column to any of the three tables silently adds an API field.

```sql
-- Fixed: the projection is the contract. Columns are chosen once, when it is built.
CREATE TABLE invoice_detail_view (
    tenant_id              uuid NOT NULL,
    invoice_id             uuid NOT NULL,
    number                 text NOT NULL,
    total                  numeric(12,2) NOT NULL,
    status                 text NOT NULL,
    customer_name          text NOT NULL,
    created_by_display_name text NOT NULL,
    PRIMARY KEY (tenant_id, invoice_id)
);
```

```typescript
// Fixed: the response type and the projection agree, and neither mentions the source tables
export type InvoiceDetail = {
  invoiceId: string;
  number: string;
  total: string;
  status: string;
  customerName: string;
  createdByDisplayName: string;
};

export async function invoiceDetail(
  tenant: TenantId,
  invoiceId: string,
): Promise<InvoiceDetail | null> {
  const [row] = await sql<InvoiceDetail[]>`
    SELECT invoice_id           AS "invoiceId",
           number,
           total::text          AS total,
           status,
           customer_name        AS "customerName",
           created_by_display_name AS "createdByDisplayName"
    FROM   invoice_detail_view
    WHERE  tenant_id = ${tenant} AND invoice_id = ${invoiceId}`;
  return row ?? null;
}
```

Why this removes the option: `fraud_score` cannot leak because the projection does not contain
it. The alternative - keep the wide view and strip fields in a serializer - fails the first time
someone adds a column and forgets the strip list, and it fails silently.

Residual gap: the projector still reads the source tables, so a careless `INSERT INTO
invoice_detail_view SELECT *` reintroduces the problem. Assert the projection's column set in a
test, so widening it is a deliberate change with a diff.

---

## Command validated against a stale read model

`A06:2025` · `CWE-367` · ASVS V2

The handler checks remaining capacity against a projection, so two concurrent commands both pass
and the invariant breaks.

```csharp
// Vulnerable: the gate is a projection that may be seconds behind
public async Task<Guid> Handle(ReserveSeat cmd, CancellationToken ct)
{
    var remaining = await _readModel.SeatsRemaining(cmd.TenantId, cmd.EventId, ct);
    if (remaining <= 0) throw new SoldOutException();

    var reservation = Reservation.Create(cmd.TenantId, cmd.EventId, cmd.ActorId);
    _db.Reservations.Add(reservation);
    await _db.SaveChangesAsync(ct);
    return reservation.Id;
}
```

Two buyers both read `1`. Both inserts succeed. The event is oversold, and the read model
eventually reports `-1`, which is the first anyone hears about it.

```sql
-- Fixed: the invariant lives on the authoritative row, enforced by the UPDATE predicate
CREATE TABLE event_capacity (
    tenant_id   uuid    NOT NULL,
    event_id    uuid    NOT NULL,
    seats_total integer NOT NULL CHECK (seats_total >= 0),
    seats_taken integer NOT NULL DEFAULT 0 CHECK (seats_taken >= 0),
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT seats_not_oversold CHECK (seats_taken <= seats_total)
);
```

```csharp
// Fixed: one conditional UPDATE decides, inside the transaction that inserts the reservation
public async Task<Guid> Handle(ReserveSeat cmd, CancellationToken ct)
{
    await using var tx = await _db.Database.BeginTransactionAsync(ct);

    var taken = await _db.Database.ExecuteSqlInterpolatedAsync($"""
        UPDATE event_capacity
        SET    seats_taken = seats_taken + 1
        WHERE  tenant_id = {cmd.TenantId}
          AND  event_id  = {cmd.EventId}
          AND  seats_taken < seats_total
        """, ct);

    if (taken == 0) throw new SoldOutException();

    var reservation = Reservation.Create(cmd.TenantId, cmd.EventId, cmd.ActorId);
    _db.Reservations.Add(reservation);
    await _db.SaveChangesAsync(ct);
    await tx.CommitAsync(ct);
    return reservation.Id;
}
```

Why checking the read model can never be correct here: a projection is a snapshot of a past
state. The gap between the check and the write is not a scheduler quantum you might lose a race
in - it is the projection lag, which is unbounded and grows with load. The conditional `UPDATE`
collapses check and act into one statement the database serialises, and the `CHECK` constraint
means even a future code path that increments directly cannot oversell.

The read model is still useful. It renders "3 seats left" on the page. It just cannot be the gate.

Residual gap: the row is now a contention point, so throughput on a single hot event is bounded
by row-lock turnover. If that is the constraint, partition capacity into buckets and reserve from
one - a deliberate design with its own fairness cost, not an accident.

---

## Projector that double-applies on redelivery

`A08:2025` · `CWE-837` · ASVS V2

At-least-once delivery is the norm. A projector that adds to a running total credits the balance
twice when the broker redelivers.

```python
# Vulnerable: src/projectors/account_balance.py
def on_payment_received(ev: PaymentReceived) -> None:
    with conn.transaction():
        conn.execute(
            "UPDATE account_balance_view "
            "SET    balance_cents = balance_cents + %s "
            "WHERE  tenant_id = %s AND account_id = %s",
            (ev.amount_cents, ev.tenant_id, ev.account_id),
        )
```

The broker redelivers when an ack times out, when the consumer restarts mid-batch, and when the
outbox relay crashes after publishing but before marking the row published. None of those is a
rare failure, and each one credits the account again.

```sql
-- Fixed: the applied-event row and the projection update share one transaction
CREATE TABLE projection_applied_event (
    projection text NOT NULL,
    event_id   uuid NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (projection, event_id)
);

CREATE INDEX projection_applied_event_applied_at_idx
    ON projection_applied_event (applied_at);
```

```python
# Fixed: claim the event, then apply it. Both commit or neither does.
PROJECTION = "account_balance_view"

def on_payment_received(ev: PaymentReceived) -> None:
    with conn.transaction():
        claimed = conn.execute(
            "INSERT INTO projection_applied_event (projection, event_id) "
            "VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING event_id",
            (PROJECTION, ev.event_id),
        ).fetchone()

        if claimed is None:
            return  # already applied; ack and move on

        conn.execute(
            "INSERT INTO account_balance_view "
            "       (tenant_id, account_id, balance_cents, last_event_seq) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, account_id) DO UPDATE "
            "SET    balance_cents  = account_balance_view.balance_cents + EXCLUDED.balance_cents, "
            "       last_event_seq = EXCLUDED.last_event_seq "
            "WHERE  account_balance_view.last_event_seq < EXCLUDED.last_event_seq",
            (ev.tenant_id, ev.account_id, ev.amount_cents, ev.seq),
        )
```

Why this removes the option: the dedupe record and the effect are in the same transaction, so
there is no window where one exists without the other. A `SELECT` followed by an `INSERT` would
leave that window open and two concurrent deliveries would both see nothing - the same TOCTOU as
the previous example. The `last_event_seq` guard adds ordering safety, so an out-of-order
redelivery is ignored rather than applied backwards.

Residual gap: `projection_applied_event` grows at the rate of your event volume. Delete rows
older than the broker's maximum redelivery window plus a margin, on a schedule, using the
`applied_at` index. Write that window down; if you cannot state it, you cannot size the retention.

---

## Dedupe set held in memory, unbounded

`API4:2023` · `CWE-770` (also `CWE-401`) · ASVS V13

The thing added to make replay safe is what kills the process.

```typescript
// Vulnerable: src/projectors/order-total.ts
const seen = new Set<string>();

export async function project(ev: DomainEvent): Promise<void> {
  if (seen.has(ev.eventId)) return;
  seen.add(ev.eventId);
  await applyToProjection(ev);
}
```

Two defects, and the second is worse. The set grows by one entry per event for the life of the
process - memory that scales with total business volume, not with concurrency, so it survives
every deploy-length window and dies at the container limit. And it is not durable: a restart
empties it, so the guard that was supposed to make redelivery safe stops working exactly when
redelivery is most likely.

Treat it as resource exhaustion, not tidiness. Anyone who can drive events - including an
authenticated user creating orders in a loop - accelerates the growth without needing a bug.

```typescript
// Fixed: durability lives in the database; the in-memory part is only a fast path
import { LRUCache } from "lru-cache";

// 20 000 entries x ~120 bytes of key and overhead is roughly 2.4 MB,
// against a 512 MB container budget. Sized from p99 events per 5 minutes.
const recentlySeen = new LRUCache<string, true>({ max: 20_000, ttl: 5 * 60_000 });

export async function project(ev: DomainEvent): Promise<void> {
  if (recentlySeen.has(ev.eventId)) return;

  await withTransaction(async (tx) => {
    const claimed = await tx.query<{ event_id: string }>(
      `INSERT INTO projection_applied_event (projection, event_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING event_id`,
      ["order_total_view", ev.eventId],
    );
    if (claimed.rowCount === 0) return;
    await applyToProjection(tx, ev);
  });

  recentlySeen.set(ev.eventId, true);
}
```

Why this removes the option: correctness no longer depends on the in-memory structure. Drop the
cache entirely and the projector is still exactly-once in effect, because the unique constraint
decides. That is the test for whether a cache is safe to add - remove it and ask whether anything
but latency changes. The `max` and `ttl` mean the cache cannot grow past a number you chose and
can defend.

Residual gap: the LRU is per process, so with several projector instances the hit rate falls and
more requests reach the database. That is a throughput question, not a correctness one. Emit the
hit rate as a metric so the size is tuned from data rather than from the number in this example.

---

## Dual write with no outbox

`A08:2025` · no CWE - integrity defect in the application's own sequencing · ASVS V2

Two systems, no transaction. This does not fail loudly; it produces missing data weeks later.

```csharp
// Vulnerable: src/Application/Invoices/ApproveInvoiceHandler.cs
public async Task Handle(ApproveInvoice cmd, CancellationToken ct)
{
    var invoice = await _invoices.Load(cmd.TenantId, cmd.InvoiceId, ct)
        ?? throw new NotFoundException();

    invoice.Approve(cmd.ActorId);
    await _db.SaveChangesAsync(ct);                       // committed

    await _broker.PublishAsync(
        new InvoiceApproved(invoice.Id, invoice.TenantId), ct);   // process dies here
}
```

The write succeeded and the event never went out, so the projection is wrong for that row
forever. No exception was thrown, no alert fired, and the log shows a successful command.
Reversing the order is worse: publishing before the commit means consumers see events for state
that was then rolled back.

```csharp
// Fixed: the event is a row written in the same transaction as the state change
public async Task Handle(ApproveInvoice cmd, CancellationToken ct)
{
    await using var tx = await _db.Database.BeginTransactionAsync(ct);

    var invoice = await _invoices.Load(cmd.TenantId, cmd.InvoiceId, ct)
        ?? throw new NotFoundException();

    invoice.Approve(cmd.ActorId);

    _db.Outbox.Add(new OutboxMessage
    {
        Id         = Guid.NewGuid(),
        TenantId   = invoice.TenantId,
        Type       = nameof(InvoiceApproved),
        Payload    = JsonSerializer.Serialize(new InvoiceApproved(invoice.Id, invoice.TenantId)),
        OccurredAt = DateTimeOffset.UtcNow,
    });

    await _db.SaveChangesAsync(ct);
    await tx.CommitAsync(ct);
}
```

```sql
-- The relay claims a batch without two workers taking the same rows
UPDATE outbox_message
SET    claimed_at = now(), claimed_by = $1
WHERE  id IN (
    SELECT id FROM outbox_message
    WHERE  published_at IS NULL
      AND (claimed_at IS NULL OR claimed_at < now() - interval '1 minute')
    ORDER  BY occurred_at
    FOR UPDATE SKIP LOCKED
    LIMIT  100
)
RETURNING id, type, payload;
```

Why this removes the option: there is one transaction, so there is no window. Either the state
change and the event both exist, or neither does. No amount of retry logic around the publish
call achieves that, because the process can die between the two calls.

Residual gap: the relay can publish and then crash before marking the row published, so consumers
get duplicates. At-least-once is the guarantee - which is why the projector needs the dedupe from
the two previous examples. Do not describe this as exactly-once. Also delete published rows on a
schedule, or the outbox becomes the largest table in the database.

---

## Stale read after write, "fixed" by reading the write store

no CWE - correctness and product defect · ASVS V2

The user saves, the page reloads, the old value appears. The tempting fix collapses the pattern.

```typescript
// Vulnerable as a design: a flag that routes reads to the write store
export async function getInvoice(
  tenant: TenantId,
  invoiceId: string,
  opts: { consistent?: boolean } = {},
): Promise<InvoiceDetail | null> {
  if (opts.consistent) {
    // reaches into the write model to avoid the lag
    const entity = await writeDb.invoice.findFirst({
      where: { tenantId: tenant, id: invoiceId },
    });
    return entity as unknown as InvoiceDetail;
  }
  return invoiceDetail(tenant, invoiceId);
}
```

Every caller that ever sees a stale value sets `consistent: true`, and within two sprints it is
the default. Three things then follow: the read store is decoration, the write store carries read
load it was not sized for, and the write entity is being cast into a response shape - so the
field-level control from the second example is gone.

```typescript
// Fixed, option A: the command returns what it did, and the client renders that
export type ApproveInvoiceResult = {
  invoiceId: string;
  status: "approved";
  version: number;      // monotonic per aggregate
};

// Fixed, option B: read-your-writes token. The client passes the version it expects.
export async function invoiceDetailAtLeast(
  tenant: TenantId,
  invoiceId: string,
  minVersion: number,
  budgetMs = 750,
): Promise<{ row: InvoiceDetail; fresh: boolean } | null> {
  const deadline = Date.now() + budgetMs;

  for (;;) {
    const [row] = await sql<(InvoiceDetail & { version: number })[]>`
      SELECT invoice_id AS "invoiceId", number, total::text AS total, status,
             customer_name AS "customerName",
             created_by_display_name AS "createdByDisplayName",
             version
      FROM   invoice_detail_view
      WHERE  tenant_id = ${tenant} AND invoice_id = ${invoiceId}`;

    if (!row) return null;
    if (row.version >= minVersion) return { row, fresh: true };
    if (Date.now() >= deadline) return { row, fresh: false };

    await new Promise((r) => setTimeout(r, 50));
  }
}
```

Why this is the honest fix: the projection stays the only read path, so its column set stays the
contract. Option A needs no waiting at all - the command knows the outcome, so the UI renders it
directly. Option B bounds the wait and, critically, returns `fresh: false` instead of hanging or
lying, so the caller can show "updating" rather than a wrong number.

Cost, stated: a `version` column on the projection and on the command result, plus a client that
carries the token. The polling loop holds a connection for up to the budget, so the budget is also
a concurrency limit - 750 ms at 200 requests per second is up to 150 in-flight waiters. Size the
pool for that or the fix becomes an availability problem.

What not to do: making the projector synchronous. That reintroduces the coupling the split was
meant to remove, and it means a projector failure fails the command.

Residual gap: eventual consistency has not been removed, only made visible. Someone has to decide
what the UI shows during the window. That is a product decision, not an implementation detail.

---

## Event schema change that breaks replay

no CWE - correctness defect · ASVS V2

The event type gained a required field. Old stored events no longer deserialize, so the
projection cannot be rebuilt - which means it cannot be fixed, migrated, or moved.

```csharp
// Vulnerable: the record was edited in place. Events written before this change
// have no tenantId in their payload, so deserialization throws on replay.
public sealed record CustomerRegistered(
    Guid   CustomerId,
    Guid   TenantId,          // added in the multi-tenancy migration
    string Email,
    DateTimeOffset OccurredAt);
```

The failure shows up months later, when someone tries to rebuild the projection to add a column
and the replay dies on event 412 of 80 million. At that point the projection is the only copy of
that data.

```csharp
// Fixed: versioned event types, an upcaster on read, both paths kept
public abstract record CustomerEvent;

public sealed record CustomerRegisteredV1(
    Guid CustomerId, string Email, DateTimeOffset OccurredAt) : CustomerEvent;

public sealed record CustomerRegisteredV2(
    Guid CustomerId, Guid TenantId, string Email, DateTimeOffset OccurredAt) : CustomerEvent;

public static class CustomerEventUpcaster
{
    // V1 predates multi-tenancy. The tenant comes from the stream the event was read
    // from, which is a recorded fact, not a guess.
    public static CustomerEvent Upcast(CustomerEvent e, Guid streamTenantId) => e switch
    {
        CustomerRegisteredV1 v1 =>
            new CustomerRegisteredV2(v1.CustomerId, streamTenantId, v1.Email, v1.OccurredAt),
        _ => e,
    };
}
```

```csharp
// The stored type name is explicit, so a class rename cannot change how old events read
private static readonly Dictionary<string, Type> EventTypes = new()
{
    ["customer.registered.v1"] = typeof(CustomerRegisteredV1),
    ["customer.registered.v2"] = typeof(CustomerRegisteredV2),
};

public static CustomerEvent Deserialize(string storedType, string payload, Guid streamTenantId)
{
    if (!EventTypes.TryGetValue(storedType, out var clrType))
        throw new UnknownEventTypeException(storedType);

    var evt = (CustomerEvent)JsonSerializer.Deserialize(payload, clrType)!;
    return CustomerEventUpcaster.Upcast(evt, streamTenantId);
}
```

Why this removes the option: the stored type name is a key in a map rather than a reflected class
name, so renaming or moving the C# type cannot change how a persisted event deserializes. Only
additive change is possible to `V2` - anything structural becomes `V3` plus an upcaster, and the
compiler forces the switch expression to be updated.

Say the rule plainly: a projection you cannot rebuild is not a projection, it is a database with
no backup. Prove rebuildability with a test that replays a fixture stream containing at least one
event of every stored version, and run it in CI. That test is what stops the in-place edit.

Residual gap: upcasters are forever, or until you rewrite the store - and each one is a decision
baked into every projection built afterwards. The tenant assigned to a V1 event above is now a
recorded fact for all time. Get that decision reviewed once rather than discovering it later.

---

## When not to use CQRS

CQRS is the most over-applied pattern in this collection. A single CRUD screen does not need two
models, two stores, and a broker. Create, edit, list, delete, one shape - splitting that buys
nothing and doubles the number of places authorization can be forgotten.

Do not split when:

- The read shape and the write shape are the same. The read model would be the write model with a
  different class name.
- The read volume is not a measured problem. "It will scale later" is not a measurement. Add an
  index.
- Nobody can yet say where authorization is enforced today. Splitting the model spreads that
  answer across two codebases.
- You need a report. A read replica and a few tuned queries give the read scaling with none of the
  lag, projectors, or replay cost.
- A business rule requires consistency. Balances, quotas, uniqueness, capacity - those need the
  authoritative store, as in the third example above.

The honest default is one model, one store, commands and queries as separate methods, and queries
returning explicit DTOs. That is free, it introduces no new failure mode, and it delivers most of
the maintainability benefit.

And the part that cannot be hidden: eventual consistency is a product decision, not an
implementation detail. The moment reads come from an asynchronous projection, someone has to
decide what a user sees in the window between their action and the update - and what happens when
that window is minutes instead of milliseconds because the queue backed up. Put that decision in
front of whoever owns the product before writing the projector, not in a comment afterwards.

## Sources

- <https://martinfowler.com/bliki/CQRS.html>
- <https://learn.microsoft.com/en-us/azure/architecture/patterns/cqrs>
- <https://microservices.io/patterns/data/transactional-outbox.html>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cwe.mitre.org/data/definitions/1220.html>
- <https://cwe.mitre.org/data/definitions/213.html>
- <https://cwe.mitre.org/data/definitions/367.html>
- <https://cwe.mitre.org/data/definitions/770.html>
- <https://cwe.mitre.org/data/definitions/837.html>
