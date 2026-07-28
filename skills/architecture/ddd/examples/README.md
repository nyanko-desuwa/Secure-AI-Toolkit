# DDD Examples
Six before/after pairs. Each names the failure in one sentence, shows the code, shows the fix, and says why the fix removes the option rather than relying on someone remembering the rule. A CWE is cited only where one genuinely applies. Several of these are correctness defects with no CWE, and saying so is more useful than forcing a mapping.
## Contents
| # | Failure | Category |
|---|---|---|
| 1 | [Anemic aggregate, invariant in a service](#1-anemic-aggregate-invariant-in-a-service) | A01, CWE-284 |
| 2 | [Aggregate boundary drawn too big](#2-aggregate-boundary-drawn-too-big) | Correctness + cost, CWE-362 |
| 3 | [Cross-aggregate invariant checked in memory](#3-cross-aggregate-invariant-checked-in-memory) | CWE-362 |
| 4 | [Handler subscribed at construction, never removed](#4-handler-subscribed-at-construction-never-removed) | CWE-401 |
| 5 | [Event published before commit](#5-event-published-before-commit) | A08, CWE-662 |
| 6 | [Repository returns the ORM entity](#6-repository-returns-the-orm-entity) | A01, CWE-284 |
---
## 1. Anemic aggregate, invariant in a service
`A01:2025` · `CWE-284` Improper Access Control · ASVS V8 The entity is public setters and the rule lives in a service, so a second caller writes the same state without the rule ever running.
```typescript
// Vulnerable
export class Timesheet {
  id!: string;
  employeeId!: string;
  status!: "draft" | "submitted" | "approved";
  hours!: number;
  approvedBy?: string;
}
export class TimesheetService {
  constructor(private repo: TimesheetRepo) {}
  async approve(id: string, approverId: string): Promise<void> {
    const ts = await this.repo.findById(id);
    if (ts.status !== "submitted") throw new Error("not_submitted");
    if (ts.employeeId === approverId) throw new Error("cannot_self_approve");
    if (ts.hours > 60) throw new Error("needs_manager_review");
    ts.status = "approved";
    ts.approvedBy = approverId;
    await this.repo.save(ts);
  }
}
```
Three rules, all correct, all bypassed by the bulk importer someone writes later:
```typescript
// The second write path. Compiles, passes review, skips every check.
for (const row of csv) {
  const ts = await repo.findById(row.id);
  ts.status = "approved";
  ts.approvedBy = row.approver;   // self-approval and 200-hour weeks now go through
  await repo.save(ts);
}
```
```typescript
// Fixed: no public mutator exists. Approval is a method on the aggregate.
export class DomainError extends Error {}
export class Timesheet {
  private constructor(
    private readonly _id: TimesheetId,
    private readonly _tenant: TenantId,
    private readonly _employeeId: EmployeeId,
    private _status: "draft" | "submitted" | "approved",
    private _hours: number,
    private _approvedBy: EmployeeId | null,
  ) {}
  static rehydrate(s: TimesheetState): Timesheet {
    return new Timesheet(
      s.id, s.tenant, s.employeeId, s.status, s.hours, s.approvedBy,
    );
  }
  get id(): TimesheetId { return this._id; }
  get status(): string { return this._status; }
  approve(approver: EmployeeId, approverLimitHours: number): void {
    if (this._status !== "submitted") throw new DomainError("not_submitted");
    if (this._employeeId === approver) throw new DomainError("cannot_self_approve");
    if (this._hours > approverLimitHours) throw new DomainError("above_approver_limit");
    this._status = "approved";
    this._approvedBy = approver;
  }
  // Snapshot for persistence. Read-only, and not a way back in.
  snapshot(): Readonly<TimesheetState> {
    return Object.freeze({
      id: this._id, tenant: this._tenant, employeeId: this._employeeId,
      status: this._status, hours: this._hours, approvedBy: this._approvedBy,
    });
  }
}
```
The importer now has one option:
```typescript
for (const row of csv) {
  const ts = await repo.find(tenant, timesheetId(row.id));
  if (!ts) continue;
  ts.approve(employeeId(row.approver), limits.forApprover(row.approver));
  await repo.save(ts);      // self-approval throws here, in the aggregate
}
```
Why the fix removes the option: `_status` is private and there is no setter. The bypass is not discouraged, it does not compile. Enforcement moved from "every caller must remember" to "the only door runs the check".
Residual gap: `snapshot()` and `rehydrate()` are a way to construct any state. Keep `rehydrate` package-internal to the persistence layer and treat it as trusted input from your own database — if a caller outside persistence can call it, you have re-opened the door. ---
## 2. Aggregate boundary drawn too big
Correctness and cost · `CWE-362` Concurrent Execution using Shared Resource with Improper Synchronization `Order` holds every line plus the customer plus inventory, so unrelated edits collide and the whole graph loads to read one field.
```python
# Vulnerable: one aggregate, everything inside it
class Order:
    def __init__(self, order_id, customer: "Customer", warehouse: "Warehouse"):
        self.id = order_id
        self.customer = customer            # whole Customer aggregate
        self.warehouse = warehouse          # whole Warehouse, with stock rows
        self.lines: list[OrderLine] = []
        self.version = 0                    # optimistic lock over the entire graph
    def change_quantity(self, sku: str, qty: int) -> None:
        for line in self.lines:
            if line.sku == sku:
                line.quantity = qty
                return
        raise DomainError("line_not_found")
```
Two consequences, both measurable:
- Two users editing different lines of a 400-line order both bump `version`. One gets a concurrency exception on a change that never conflicted.
- The order detail page loads 400 lines, the customer, and the warehouse's stock rows to render a header.
```python
# Fixed: aggregate sized to the invariant; other aggregates by ID
class Order:
    MAX_LINES = 200
    def __init__(
        self,
        order_id: OrderId,
        tenant: TenantId,
        customer_id: CustomerId,        # ID, not the object
        warehouse_id: WarehouseId,
        credit_limit: Money,            # value copied in at construction
    ):
        self._id = order_id
        self._tenant = tenant
        self._customer_id = customer_id
        self._warehouse_id = warehouse_id
        self._credit_limit = credit_limit
        self._lines: list[OrderLine] = []
        self._version = 0
    def change_quantity(self, sku: Sku, qty: int) -> None:
        if qty < 1:
            raise DomainError("invalid_quantity")
        for i, line in enumerate(self._lines):
            if line.sku == sku:
                candidate = self._total_excluding(sku) + line.unit_price * qty
                if candidate > self._credit_limit:
                    raise DomainError("credit_limit_exceeded")
                self._lines[i] = OrderLine(sku, qty, line.unit_price)
                return
        raise DomainError("line_not_found")
```
The invariant that justifies keeping lines inside `Order` is `total <= credit_limit` — you cannot check it without seeing all the lines. Stock levels have no such relationship to an order's total, so `Warehouse` is a separate aggregate with its own transaction. Reads go to a projection, not the aggregate:
```python
# Read side. No aggregate, no invariant, one query, explicit bound.
def order_header(conn, tenant: TenantId, order_id: OrderId) -> dict | None:
    row = conn.execute(
        """
        SELECT o.id, o.status, o.total_minor_units, o.currency,
               o.line_count, c.display_name AS customer_name
        FROM sales.order_summary o
        JOIN sales.customer_name c ON c.customer_id = o.customer_id
        WHERE o.tenant_id = %s AND o.id = %s
        """,
        (str(tenant), str(order_id)),
    ).fetchone()
    return dict(row) if row else None
```
Why the fix removes the failure: the collision disappears because the version now covers only state that genuinely shares an invariant. The load cost disappears because the read path no longer goes through the write model at all. See `skills/architecture/cqrs/` for the read-model side of this.
Residual gap: if lines can legitimately reach the thousands, `Order` is still too big and the credit-limit invariant needs a different home — a running total maintained on the root, with a documented answer for how it stays correct. Splitting lines into their own aggregate makes that invariant cross-aggregate, which is example 3. ---
## 3. Cross-aggregate invariant checked in memory
`CWE-362` Concurrent Execution using Shared Resource with Improper Synchronization · ASVS V2 (Validation and Business Logic) The rule spans two aggregates, so it is checked after loading both, and two concurrent transactions each see a state where the rule holds.
```python
# Vulnerable: "a team may have at most 5 active members" checked across two aggregates
def add_member(team_id: str, user_id: str) -> None:
    team = team_repo.find(team_id)
    members = membership_repo.list_active(team_id)     # separate aggregate per membership
    if len(members) >= team.max_members:
        raise DomainError("team_full")
    membership_repo.add(Membership(team_id, user_id))  # commit
```
Two requests arriving together both read four members, both pass, both insert. The team now has six. This is not a code-reading bug — it is only visible if you ask what happens when the same function runs twice concurrently. Two honest fixes. Pick one and say which. Fix A — make it one aggregate, so the database enforces the boundary:
```python
# Fixed A: memberships live inside Team. One row, one lock, one version.
class Team:
    def __init__(self, team_id: TeamId, tenant: TenantId, max_members: int):
        self._id = team_id
        self._tenant = tenant
        self._max_members = max_members
        self._members: set[UserId] = set()
        self._version = 0
    def add_member(self, user: UserId) -> None:
        if user in self._members:
            return                                  # idempotent
        if len(self._members) >= self._max_members:
            raise DomainError("team_full")
        self._members.add(user)
```
```python
# The repository makes the concurrency guarantee explicit.
def save(self, team: Team) -> None:
    result = self._conn.execute(
        """
        UPDATE teams.team
           SET members = %s, version = version + 1
         WHERE id = %s AND tenant_id = %s AND version = %s
        """,
        (json.dumps(sorted(str(m) for m in team.members)),
         str(team.id), str(team.tenant), team.version),
    )
    if result.rowcount == 0:
        raise ConcurrencyError("team_modified_concurrently")   # caller retries
```
Fix B — keep them separate and enforce the count at the database:
```sql
-- Fixed B: the invariant as a constraint the application cannot race
CREATE TABLE teams.membership (
    tenant_id  uuid    NOT NULL,
    team_id    uuid    NOT NULL,
    user_id    uuid    NOT NULL,
    slot       int     NOT NULL CHECK (slot BETWEEN 1 AND 5),
    PRIMARY KEY (tenant_id, team_id, user_id),
    UNIQUE (tenant_id, team_id, slot)
);
-- Two concurrent inserts competing for slot 5: one commits, one gets a
-- unique-violation. The application maps that to "team_full".
```
Why the fixes remove the failure: both move the check to something that serialises. Fix A uses a version predicate so the second write fails; Fix B uses a unique constraint so the second insert fails. The in-memory `if` never had that property no matter how carefully it was written.
Residual gap and the honest third option: if the rule genuinely must span aggregates and you cannot serialise it — a limit spanning two services, for instance — then it is eventually consistent. Say that out loud, define the compensating action (revoke the sixth membership and notify), and accept that the system is briefly wrong. Eventual consistency here is a correctness cost you chose, not a free scaling win. ---
## 4. Handler subscribed at construction, never removed
`CWE-401` Missing Release of Memory after Effective Lifetime · `A06:2025` A handler registered in a constructor with no removal point accumulates one closure per instance, and each closure retains everything it captured.
```typescript
// Vulnerable: one subscription per instance, on an application-lifetime bus.
// In a worker that builds a handler per message, this grows without limit.
export class InvoiceNotifier {
  constructor(
    private readonly bus: EventBus,
    private readonly requestContext: RequestContext,   // retained forever
    private readonly mailer: Mailer,
  ) {
    bus.on("InvoiceApproved", (e) => this.notify(e));  // no handle returned or kept
  }
  private async notify(e: InvoiceApproved): Promise<void> {
    await this.mailer.send(this.requestContext.userEmail, `Invoice ${e.invoiceId}`);
  }
}
```
Two failures compound. Memory grows by one closure and one `RequestContext` per instance. And because every past subscription is still live, one `InvoiceApproved` sends N emails — the duplicate-delivery symptom that usually gets misdiagnosed as a broker problem.
```typescript
// Fixed: subscription returns a disposer, ownership is explicit, and the handler
// resolves its per-message context instead of capturing it.
export type Unsubscribe = () => void;
export interface EventBus {
  on<E>(type: string, handler: (e: E) => Promise<void>): Unsubscribe;
  emit<E>(type: string, event: E): Promise<void>;
}
export class InvoiceNotifier implements AsyncDisposable {
  private readonly disposers: Unsubscribe[] = [];
  constructor(
    private readonly bus: EventBus,
    private readonly mailer: Mailer,
    private readonly recipients: RecipientLookup,   // resolved per event, not captured
  ) {}
  start(): void {
    if (this.disposers.length) throw new Error("already_started");
    this.disposers.push(
      this.bus.on<InvoiceApproved>("InvoiceApproved", (e) => this.notify(e)),
    );
  }
  private async notify(e: InvoiceApproved): Promise<void> {
    const to = await this.recipients.forInvoice(e.tenantId, e.invoiceId);
    if (!to) return;
    await this.mailer.send(to, `Invoice ${e.invoiceId}`);
  }
  async [Symbol.asyncDispose](): Promise<void> {
    while (this.disposers.length) this.disposers.pop()!();
  }
}
```
Wiring: one long-lived instance, started at boot, disposed at shutdown.
```typescript
const notifier = new InvoiceNotifier(bus, mailer, recipients);
notifier.start();
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    void notifier[Symbol.asyncDispose]().finally(() => process.exit(0));
  });
}
```
Why the fix removes the failure: `on` cannot be called without producing a disposer, and `start()` throws if called twice, so the accumulating path is gone by construction. The handler no longer closes over request state, so nothing per-request is retained even if a subscription outlives its intent.
Residual gap: this is source-level reasoning. Whether the process actually releases the memory depends on what else holds a reference — verify with a heap snapshot before and after a load run. `skills/architecture/performance/` has the diagnosis procedure. ---
## 5. Event published before commit
`A08:2025` Software or Data Integrity Failures · `CWE-662` Improper Synchronization · ASVS V2 The event goes out inside the transaction, so a consumer acts on state that then rolls back.
```csharp
// Vulnerable: publish inside the transaction, before the commit that may not happen
public async Task ApproveAsync(TenantId tenant, InvoiceId id, UserId actor, CancellationToken ct)
{
    await using var tx = await _db.Database.BeginTransactionAsync(ct);
    var invoice = await _repo.FindAsync(tenant, id, ct)
                  ?? throw new NotFoundException();
    invoice.Approve(actor);
    await _bus.PublishAsync(new InvoiceApproved(tenant, id, actor), ct);  // fired now
    await _db.SaveChangesAsync(ct);   // unique violation here rolls back the approval
    await tx.CommitAsync(ct);         // ...but the payment was already released
}
```
The payment worker has already moved money against an approval that no longer exists. There is no code path that reverses it, because nobody wrote one for a case they did not expect.
```csharp
// Fixed: the aggregate records events; the outbox row is written in the same transaction
public sealed class Invoice
{
    private readonly List<IDomainEvent> _events = new();
    public IReadOnlyList<IDomainEvent> PullEvents()
    {
        var copy = _events.ToArray();
        _events.Clear();
        return copy;
    }
    public void Approve(UserId actor)
    {
        if (Status != InvoiceStatus.Submitted) throw new DomainException("not_submitted");
        if (actor == SubmittedBy) throw new DomainException("cannot_self_approve");
        Status = InvoiceStatus.Approved;
        ApprovedBy = actor;
        ApprovedAt = DateTimeOffset.UtcNow;
        _events.Add(new InvoiceApproved(TenantId, Id, actor, ApprovedAt.Value));
    }
}
public async Task ApproveAsync(TenantId tenant, InvoiceId id, UserId actor, CancellationToken ct)
{
    await using var tx = await _db.Database.BeginTransactionAsync(ct);
    var invoice = await _repo.FindAsync(tenant, id, ct)
                  ?? throw new NotFoundException();
    invoice.Approve(actor);
    foreach (var evt in invoice.PullEvents())
        _db.Outbox.Add(new OutboxMessage(
            Id: Guid.NewGuid(),
            TenantId: tenant,
            Type: evt.GetType().Name,
            Payload: JsonSerializer.Serialize(evt, _jsonOptions),
            OccurredAt: DateTimeOffset.UtcNow));
    await _db.SaveChangesAsync(ct);   // state change and outbox row: one atomic write
    await tx.CommitAsync(ct);
}
```
A separate worker drains the outbox:
```csharp
public async Task DrainAsync(CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var batch = await db.Outbox
            .Where(m => m.DispatchedAt == null)
            .OrderBy(m => m.OccurredAt)
            .Take(100)                                  // bounded batch
            .ToListAsync(ct);
        if (batch.Count == 0) { await Task.Delay(500, ct); continue; }
        foreach (var m in batch)
        {
            await _bus.PublishAsync(m.Type, m.Payload, m.Id, ct);  // Id = idempotency key
            m.DispatchedAt = DateTimeOffset.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }
}
```
Why the fix removes the failure: the event and the state change are the same write. If the transaction rolls back, the outbox row is gone too, so there is nothing to publish. The ordering hazard is not mitigated, it is structurally impossible. Consequence you must accept and design for: this is at-least-once delivery. The publish can succeed and the `DispatchedAt` update fail, so a consumer will occasionally see a duplicate. Every consumer keys on the message ID and skips a repeat. Also give the outbox table a retention job — undrained and dispatched rows both accumulate, and an unbounded table is its own availability problem. ---
## 6. Repository returns the ORM entity
`A01:2025` · `CWE-284` Improper Access Control · ASVS V8 The repository hands out the tracked persistence object, so the caller mutates state directly and both the invariants and the tenant filter are outside the boundary.
```csharp
// Vulnerable: IQueryable out. Filtering, including tenancy, happens in the caller.
public interface IAccountRepository
{
    IQueryable<AccountRow> Query();
}
// Caller one, correct by accident:
var mine = repo.Query().Where(a => a.TenantId == tenant && a.Id == id).First();
// Caller two, written under time pressure:
var acct = repo.Query().First(a => a.Id == id);   // any tenant's account
acct.CreditLimitMinorUnits = 5_000_000;           // no invariant, no audit, no event
acct.Status = "ACTIVE";                           // reactivates a closed account
await db.SaveChangesAsync();
```
Nothing about caller two looks wrong in a diff. The tenant predicate is absent rather than incorrect, and absence does not show up in a review of the lines that changed.
```csharp
// Fixed: the repository returns aggregates, takes the tenant, and bounds every list
public interface IAccountRepository
{
    Task<Account?> FindAsync(TenantId tenant, AccountId id, CancellationToken ct);
    Task<IReadOnlyList<Account>> ListActiveAsync(
        TenantId tenant, int limit, CancellationToken ct);
    Task SaveAsync(Account account, CancellationToken ct);
}
public sealed class Account
{
    private Account(AccountId id, TenantId tenant, Money creditLimit, AccountStatus status)
        => (Id, Tenant, _creditLimit, _status) = (id, tenant, creditLimit, status);
    public AccountId Id { get; }
    public TenantId Tenant { get; }
    private Money _creditLimit;
    private AccountStatus _status;
    private readonly List<IDomainEvent> _events = new();
    public void RaiseCreditLimit(Money newLimit, UserId actor, Money actorApprovalCeiling)
    {
        if (_status != AccountStatus.Active)
            throw new DomainException("account_not_active");
        if (newLimit <= _creditLimit)
            throw new DomainException("not_an_increase");
        if (newLimit > actorApprovalCeiling)
            throw new DomainException("above_actor_ceiling");
        var previous = _creditLimit;
        _creditLimit = newLimit;
        _events.Add(new CreditLimitRaised(Tenant, Id, previous, newLimit, actor));
    }
    internal static Account Rehydrate(AccountRow row) => new(
        new AccountId(row.Id), new TenantId(row.TenantId),
        new Money(row.CreditLimitMinorUnits, row.Currency),
        Enum.Parse<AccountStatus>(row.Status));
    internal AccountRow ToRow() => new()
    {
        Id = Id.Value, TenantId = Tenant.Value,
        CreditLimitMinorUnits = _creditLimit.MinorUnits,
        Currency = _creditLimit.Currency, Status = _status.ToString(),
    };
}
public sealed class AccountRepository : IAccountRepository
{
    private readonly AppDbContext _db;
    public AccountRepository(AppDbContext db) => _db = db;
    public async Task<Account?> FindAsync(TenantId tenant, AccountId id, CancellationToken ct)
    {
        var row = await _db.Accounts.AsNoTracking().SingleOrDefaultAsync(
            a => a.Id == id.Value && a.TenantId == tenant.Value, ct);
        return row is null ? null : Account.Rehydrate(row);
    }
    public async Task<IReadOnlyList<Account>> ListActiveAsync(
        TenantId tenant, int limit, CancellationToken ct)
    {
        var rows = await _db.Accounts.AsNoTracking()
            .Where(a => a.TenantId == tenant.Value && a.Status == "ACTIVE")
            .OrderBy(a => a.Id)
            .Take(Math.Clamp(limit, 1, 200))            // no unbounded read
            .ToListAsync(ct);
        return rows.Select(Account.Rehydrate).ToList();
    }
    public async Task SaveAsync(Account account, CancellationToken ct)
    {
        var row = account.ToRow();
        _db.Accounts.Update(row);
        await _db.SaveChangesAsync(ct);
    }
}
```
Why the fix removes the option: `TenantId` is a required parameter on every method, so a caller cannot forget it — it is a compile error, not an omission. `Account` exposes no setter, so the only route to a new credit limit runs the three checks and records the event. Caller two's code no longer has a form that compiles.
Residual gaps, stated rather than implied:
- `AsNoTracking` plus `Rehydrate`/`ToRow` means an extra mapping step and a full-row update. That is real cost. It buys you a persistence model that cannot be mutated from a handler.
- `internal` on `Rehydrate` and `ToRow` only holds within the assembly. Split persistence into its own project if you need the compiler to enforce it across module lines.
- Nothing here stops a raw SQL query from bypassing the repository entirely. Enforce that with a per-context database role that has no grant outside its own schema — see [best-practices.md](../best-practices.md#bounded-context-is-a-trust-boundary). ---
