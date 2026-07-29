# Examples

Six runnable before/after pairs. Commands use only language standard libraries. Vulnerable blocks
are teaching material, not templates.

## 1. TypeScript: Caller Authorization versus Actor-Scoped API

`A01:2025` · ASVS V8 · `CWE-602`, `CWE-1220`

Vulnerable: the controller checks permission, but the exported module method accepts no actor. A job
can call it directly.

```typescript
// vulnerable.ts - run: npx tsx vulnerable.ts
class Billing {
  approve(invoiceId: string): void { console.log(`approved:${invoiceId}`); }
}
const billing = new Billing();
const controller = (permissions: Set<string>) => {
  if (!permissions.has("invoice:approve")) throw new Error("forbidden");
  billing.approve("invoice-1");
};
controller(new Set(["invoice:approve"]));
billing.approve("invoice-2"); // background caller bypasses the controller
```

Fixed: the owner requires and checks an actor. Every caller has the same path.

```typescript
// fixed.ts - run: npx tsx fixed.ts
type Actor = Readonly<{ tenantId: string; permissions: ReadonlySet<string> }>;
type Invoice = { id: string; tenantId: string; status: "submitted" | "approved" };

class Billing {
  constructor(private readonly rows: Invoice[]) {}
  approve(actor: Actor, invoiceId: string): void {
    if (!actor.permissions.has("invoice:approve")) throw new Error("forbidden");
    const row = this.rows.find(x => x.id === invoiceId && x.tenantId === actor.tenantId);
    if (!row) throw new Error("not_found");
    row.status = "approved";
  }
}
const rows: Invoice[] = [{ id: "invoice-1", tenantId: "tenant-a", status: "submitted" }];
const billing = new Billing(rows);
billing.approve({ tenantId: "tenant-a", permissions: new Set(["invoice:approve"]) }, "invoice-1");
console.log(rows[0].status);
```

Security: the owner enforces permission and tenant scope. Cost: one actor object and a required
lookup predicate; real persistence should index tenant plus ID.

## 2. Java: Cross-Module Mutable Repository versus Contract DTO

`A01:2025` · ASVS V8, V15 · `CWE-653`

Vulnerable: another module receives mutable owned state and can change it without the owner's rule.

```java
// Vulnerable.java - javac Vulnerable.java && java Vulnerable
import java.util.*;
class Vulnerable {
  static final class Account { String tenant, status; Account(String t){ tenant=t; status="OPEN"; } }
  static final class AccountsRepository {
    final Map<String,Account> rows = new HashMap<>();
    Account find(String id) { return rows.get(id); }
  }
  public static void main(String[] args) {
    var repo = new AccountsRepository(); repo.rows.put("account-1", new Account("tenant-a"));
    repo.find("account-1").status = "CLOSED"; // caller bypasses owner and tenant scope
    System.out.println(repo.find("account-1").status);
  }
}
```

Fixed: callers depend on an immutable public contract. The owner applies scope and mutation rules.

```java
// Fixed.java - javac Fixed.java && java Fixed
import java.util.*;
class Fixed {
  record Actor(String tenantId, Set<String> permissions) {
    Actor { permissions = Set.copyOf(permissions); }
  }
  record AccountView(String id, String status) {}
  interface AccountsApi { Optional<AccountView> close(Actor actor, String id); }
  static final class AccountsModule implements AccountsApi {
    private static final class Account { String tenant, status="OPEN"; Account(String t){tenant=t;} }
    private final Map<String,Account> rows = new HashMap<>();
    AccountsModule(){ rows.put("account-1", new Account("tenant-a")); }
    public Optional<AccountView> close(Actor actor, String id) {
      if (!actor.permissions().contains("account:close")) throw new SecurityException("forbidden");
      var a=rows.get(id); if (a==null || !a.tenant.equals(actor.tenantId())) return Optional.empty();
      if (!a.status.equals("OPEN")) throw new IllegalStateException("not_open");
      a.status="CLOSED"; return Optional.of(new AccountView(id,a.status));
    }
  }
  public static void main(String[] args) {
    AccountsApi api=new AccountsModule();
    System.out.println(api.close(new Actor("tenant-a",Set.of("account:close")),"account-1"));
  }
}
```

Security: private state cannot cross the contract. Cost: one DTO allocation; it prevents retained
ORM entities and accidental full-row serialization.

## 3. Python: Transaction Held Across Module Call

`A06:2025` · `A10:2025` · ASVS V15, V16 · `CWE-772`

Vulnerable: a database transaction remains open while a slow dependency runs.

```python
# vulnerable.py - python vulnerable.py
import sqlite3, time
conn = sqlite3.connect(":memory:")
conn.execute("create table orders(id text primary key, status text)")
def remote_price() -> int:
    time.sleep(1)
    return 125
conn.execute("begin immediate")
price = remote_price()  # lock and connection held across module/network work
conn.execute("insert into orders values (?, ?)", ("order-1", f"priced:{price}"))
conn.commit()
print("done")
```

Fixed: call before opening the local transaction, then write local state plus outbox atomically.

```python
# fixed.py - python fixed.py
import json, sqlite3, time, uuid
conn = sqlite3.connect(":memory:")
conn.executescript("""
create table orders(id text primary key, status text);
create table outbox(id text primary key, kind text, payload text);
""")
def remote_price() -> int:
    time.sleep(0.01)
    return 125
price = remote_price()
with conn:
    conn.execute("insert into orders values (?, ?)", ("order-1", f"priced:{price}"))
    conn.execute("insert into outbox values (?, ?, ?)",
                 (str(uuid.uuid4()), "OrderPlaced.v1", json.dumps({"orderId":"order-1"})))
print(conn.execute("select count(*) from outbox").fetchone()[0])
```

Security: one owner controls commit and publication intent. Cost: price may become stale; include a
quote version/expiry and bounded retry where business rules require freshness.

## 4. TypeScript: Global Listener Leak

`A06:2025` · ASVS V15, V16 · `CWE-770`, `CWE-772`

Vulnerable: every request adds a process-lifetime listener that captures tenant state.

```typescript
// vulnerable-listener.ts - run: npx tsx vulnerable-listener.ts
import { EventEmitter } from "node:events";
const bus = new EventEmitter();
function request(tenantId: string): void {
  bus.on("paid", (id: string) => console.log(tenantId, id));
}
for (let i=0;i<20;i++) request(`tenant-${i}`);
console.log(bus.listenerCount("paid")); // 20; each tenant closure remains
```

Fixed: one host-owned listener; tenant data comes from the event, and shutdown removes it.

```typescript
// fixed-listener.ts - run: npx tsx fixed-listener.ts
import { EventEmitter } from "node:events";
type Paid = Readonly<{ tenantId: string; invoiceId: string }>;
const bus = new EventEmitter();
const onPaid = (e: Paid) => console.log(e.tenantId, e.invoiceId);
bus.on("paid", onPaid);
bus.emit("paid", { tenantId: "tenant-a", invoiceId: "invoice-1" });
bus.off("paid", onPaid);
console.log(bus.listenerCount("paid")); // 0
```

Security: stale tenant/actor context is not retained or replayed. Cost: one stable handler; per-event
lookups may be needed instead of captured request services.

## 5. Java: Unbounded Queue versus Backpressure

`A06:2025` · ASVS V15, V16 · `CWE-770`

Vulnerable: an unbounded queue grows whenever producers outrun the consumer.

```java
// VulnerableQueue.java - javac VulnerableQueue.java && java VulnerableQueue
import java.util.concurrent.*;
class VulnerableQueue {
  public static void main(String[] args) {
    BlockingQueue<String> q = new LinkedBlockingQueue<>();
    for (int i=0;i<100000;i++) q.add("event-"+i);
    System.out.println(q.size());
  }
}
```

Fixed: capacity is explicit, saturation rejects and can be measured/retried.

```java
// FixedQueue.java - javac FixedQueue.java && java FixedQueue
import java.util.concurrent.*;
class FixedQueue {
  public static void main(String[] args) {
    BlockingQueue<String> q = new ArrayBlockingQueue<>(1000);
    int rejected=0;
    for (int i=0;i<100000;i++) if (!q.offer("event-"+i)) rejected++;
    System.out.println("depth="+q.size()+", rejected="+rejected);
  }
}
```

Security: callers cannot drive process memory without a ceiling. Cost: work is rejected at capacity;
production code must expose metrics and a safe retry or durable-transport policy.

## 6. Python: Lazy Iterator Hides a Cursor

`A10:2025` · ASVS V16 · `CWE-772`

Vulnerable: a module returns a generator backed by an open connection. A caller that stops early
leaves release timing to generator finalization.

```python
# vulnerable_cursor.py - python vulnerable_cursor.py
import sqlite3
def rows():
    conn=sqlite3.connect(":memory:")
    conn.execute("create table item(id integer)")
    conn.executemany("insert into item values (?)", [(1,), (2,)])
    for row in conn.execute("select id from item"):
        yield row[0]
    conn.close()
it=rows(); print(next(it))  # caller never exhausts or closes it
```

Fixed: materialize a bounded page and release the handle inside the owning module.

```python
# fixed_cursor.py - python fixed_cursor.py
import sqlite3
def page(limit: int) -> list[int]:
    safe_limit=max(1,min(limit,100))
    with sqlite3.connect(":memory:") as conn:
        conn.execute("create table item(id integer)")
        conn.executemany("insert into item values (?)", [(1,), (2,)])
        return [r[0] for r in conn.execute(
            "select id from item order by id limit ?", (safe_limit,)
        ).fetchall()]
print(page(10))
```

Security: callers cannot keep private database handles alive or compose unscoped predicates.
Cost: materialization allocates the page, so its maximum is mandatory.
