# Microservices Before and After Examples

These are eight small, runnable pairs. They use synthetic values only. TypeScript examples run with `npx tsx file.ts`; Go examples use `go run`; Python examples use Python 3.11. They demonstrate a boundary mechanism, not a production framework. Blocks marked Vulnerable must not be copied.

## 1. Gateway-only authorization

`A01:2025` · ASVS V8 · CWE-1220

```typescript
// Vulnerable: gateway authorizes tenant, owner trusts ID.
const request = { tenantId: "tenant-0002", orderId: "order-0001" };
function getOrder(r: typeof request) { return `returned ${r.orderId} for ${r.tenantId}`; }
console.log(getOrder(request));
```

```typescript
// Fixed: owner loads and scopes the object.
const orders = new Map([["order-0001", { tenant: "tenant-0001" }]]);
function getOrder(subjectTenant: string, orderId: string): string {
  const order = orders.get(orderId);
  if (!order || order.tenant !== subjectTenant) throw new Error("not found");
  return `returned ${orderId}`;
}
console.log(getOrder("tenant-0001", "order-0001"));
```

Why it holds: the protected object decides. Cost: an owner read; cache only with bounded stale-policy time. Residual gap: live gateway bypasses need runtime testing.

---

## 2. mTLS mistaken for authorization

`A01:2025` · ASVS V8/V12 · CWE-602

```go
package main
import "fmt"
// Vulnerable: an authenticated peer can request any object.
func get(peer, object string) string { if peer != "orders-service" { return "forbidden" }; return "data:" + object }
func main(){ fmt.Println(get("orders-service", "invoice-0002")) }
```

```go
package main
import "fmt"
type Object struct { tenant string }
// Fixed: transport peer and object tenant are separate checks.
func get(peer, subjectTenant string, o Object) string {
 if peer != "orders-service" || subjectTenant != o.tenant { return "forbidden" }
 return "authorized"
}
func main(){ fmt.Println(get("orders-service", "tenant-0001", Object{"tenant-0001"})) }
```

Why it holds: certificate identity grants no object access. Cost: policy input and owner lookup. Residual gap: the sample does not implement certificate verification.

---

## 3. Confused deputy

`A01:2025` · ASVS V8/V15 · CWE-441

```python
# Vulnerable: billing's broad authority is spent for any caller-supplied user.
def charge(user_id: str, cents: int) -> str:
    return f"charged {user_id} {cents}"
print(charge("user-0002", 5000))
```

```python
# Fixed: a bounded subject and owner policy decide the action.
ACTORS = {"user-0001": {"tenant": "tenant-0001", "may_charge": True}}
INVOICES = {"invoice-0001": {"tenant": "tenant-0001", "cents": 5000}}
def charge(subject: str, invoice_id: str) -> str:
    actor, invoice = ACTORS.get(subject), INVOICES.get(invoice_id)
    if not actor or not actor["may_charge"] or not invoice or actor["tenant"] != invoice["tenant"]:
        raise PermissionError("forbidden")
    return f"charged {invoice_id} {invoice['cents']}"
print(charge("user-0001", "invoice-0001"))
```

Why it holds: callers cannot choose an unrelated principal, amount, or tenant. Cost: current authorization reads; revocation cache needs a TTL. Residual gap: external payment idempotency is still required.

---

## 4. Shared database boundary

`A06:2025` · ASVS V8/V15 · CWE-653

```sql
-- Vulnerable: both service credentials can mutate the same owner table.
GRANT SELECT, INSERT, UPDATE, DELETE ON billing.invoice TO shared_app;
```

```sql
-- Fixed: the owner writes; another service receives a narrow projection.
GRANT SELECT, INSERT, UPDATE, DELETE ON billing.invoice TO billing_writer;
GRANT SELECT ON billing.invoice_summary TO reporting_reader;
```

Why it holds: reporting cannot bypass billing's mutation policy. Cost: projection lag and storage, or a network call. Residual gap: database superusers and migrations can still bypass application boundaries.

---

## 5. Discovery-mediated SSRF

`A01:2025` · ASVS V4/V15 · CWE-918

```python
# Vulnerable: request input chooses an outbound destination.
from urllib.request import urlopen
def fetch(url: str) -> bytes: return urlopen(url, timeout=2).read(1024)
print(fetch("https://service.invalid/health"))
```

```python
# Fixed: only an approved logical dependency is resolvable.
from urllib.parse import urlparse
TARGETS = {"catalog": "https://catalog.service.invalid/health"}
def fetch(name: str) -> str:
    url = TARGETS.get(name)
    if not url: raise ValueError("unknown dependency")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password: raise ValueError("bad target")
    return parsed.geturl()
print(fetch("catalog"))
```

Why it holds: the caller cannot select arbitrary URLs. Cost: routing configuration and egress policy. Residual gap: DNS rebinding and redirects require an HTTP client and network controls that the sample does not implement.

---

## 6. Event payload treated as authority

`A01:2025` · ASVS V8/V15 · CWE-602

```typescript
// Vulnerable: event chooses role and amount.
type Event = { role: string; amount: number };
function handle(e: Event) { if (e.role === "admin") console.log("grant", e.amount); }
handle({ role: "admin", amount: 9000 });
```

```typescript
// Fixed: event carries identifiers; owner resolves authority and value.
const actors = new Map([["user-0001", { admin: true }]]);
const grants = new Map([["grant-0001", { amount: 9000 }]]);
type Event = { actorId: string; grantId: string };
function handle(e: Event) {
  const actor = actors.get(e.actorId), grant = grants.get(e.grantId);
  if (!actor?.admin || !grant) throw new Error("forbidden");
  console.log("grant", grant.amount);
}
handle({ actorId: "user-0001", grantId: "grant-0001" });
```

Why it holds: origin or broker membership cannot override current owner policy. Cost: reads and duplicate handling. Residual gap: broker ACL and TLS remain deployment controls.

---

## 7. Retry storm and multiplied pools

`A10:2025` · ASVS V15/V16 · CWE-799

```python
# Vulnerable: every branch retries independently forever.
def request(dependencies, call):
    for dependency in dependencies:
        while True:
            try: call(dependency); break
            except TimeoutError: pass
request(["a", "b", "c"], lambda _: (_ for _ in ()).throw(TimeoutError()))
```

```go
package main
import "fmt"
// Fixed: capacity is calculated and attempts are finite.
func upper(replicas, dependencies, pool int) int { return replicas * dependencies * pool }
func main(){ fmt.Println("connections", upper(6, 4, 10), "max attempts per branch", 3) }
```

Why it holds: a finite budget replaces an outage-amplifying loop. Cost: rejected or delayed work and capacity planning. Residual gap: a real client still needs deadline, jitter, idempotency, and shared retry-budget enforcement.

---

## 8. Unbounded saga and telemetry state

`A06:2025` · ASVS V13/V15/V16 · CWE-770

```python
# Vulnerable: arbitrary keys retain full context and labels forever.
sagas = {}
metrics = {}
for n in range(10000):
    sagas[f"request-{n}"] = {"payload": "sensitive-test-context"}
    metrics[f"tenant-{n}"] = 1
print(len(sagas), len(metrics))
```

```python
# Fixed: minimal state, finite capacity, expiry, and bounded metric labels.
from collections import OrderedDict
from datetime import datetime, timedelta, UTC
sagas = OrderedDict(); MAX = 1000; expiry = datetime.now(UTC) + timedelta(hours=1)
def save(saga_id: str, object_id: str) -> None:
    if len(sagas) >= MAX: raise RuntimeError("saga capacity reached")
    sagas[saga_id] = {"object_id": object_id, "expires": expiry}
def metric(operation: str) -> None:
    if operation not in {"create", "complete", "compensate", "expire"}: return
    print(operation)
save("saga-0001", "order-0001"); metric("create"); print(len(sagas))
```

Why it holds: retained context and label cardinality have explicit limits. Cost: capacity failures and loss of arbitrary per-tenant diagnostics. Residual gap: durable expiry, encryption, recovery ownership, and distributed metric configuration require deployment verification.

## Sources

- [OWASP mapping](../references/owasp-mapping.md)
- [Verified CWE entries](../references/cwe-microservices.md)
