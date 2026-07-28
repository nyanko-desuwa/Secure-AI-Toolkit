# Best Practices

Each pattern names the boundary it protects and the runtime cost it introduces. Code labelled Vulnerable is intentionally unsafe.

## 1. Authorize the object at its owner

The billing service must not trust an upstream `tenantId` or a gateway decision. Load the object under the authenticated subject's scope and authorize the action locally.

```typescript
// Vulnerable: npm install express && npx tsx app.ts
import express from "express";
const app = express(); app.use(express.json());
app.post("/refunds/:id", (req, res) => {
  if (req.header("x-caller-service") !== "orders") return res.sendStatus(403);
  res.json({ refunded: req.params.id, tenant: req.body.tenantId });
});
app.listen(3000);
```

The caller service name says who connected. It says nothing about the object.

```typescript
// Fixed: npm install express && npx tsx app.ts
import express from "express";
const app = express();
const refunds = new Map([["refund-0001", { tenant: "tenant-0001", status: "open" }]]);
app.post("/refunds/:id", (req, res) => {
  const subject = req.header("x-verified-subject");
  const tenant = req.header("x-verified-tenant");
  if (!subject || !tenant) return res.sendStatus(401);
  const refund = refunds.get(req.params.id);
  if (!refund || refund.tenant !== tenant) return res.sendStatus(404);
  if (refund.status !== "open") return res.status(409).json({ error: "not refundable" });
  refund.status = "refunded";
  res.json({ refunded: req.params.id });
});
app.listen(3000);
```

Security: owner-side object authorization prevents broken object access and confused-deputy use (A01:2025, ASVS V8, CWE-1220/CWE-441). Cost: one scoped read per operation and policy evaluation. Cache only bounded, short-lived decisions; revocation is stale for the TTL.

## 2. Separate workload identity from user authority

Use the authenticated workload identity to decide whether service A may call an endpoint. Carry end-user context as a distinct, audience-bound assertion. The owner validates it and applies current policy.

```go
package main
import ("fmt"; "time")
type Context struct { Subject, Audience, Action string; Expires time.Time }
func authorize(peer, wantAudience string, c Context) error {
 if peer != "orders-service" { return fmt.Errorf("unknown workload") }
 if c.Subject == "" || c.Audience != wantAudience || c.Action != "invoice:read" { return fmt.Errorf("bad context") }
 if !c.Expires.After(time.Now()) { return fmt.Errorf("expired") }
 return nil
}
func main(){ c:=Context{"user-0001","billing-service","invoice:read",time.Now().Add(time.Minute)}; fmt.Println(authorize("orders-service","billing-service",c)) }
```

Security: mTLS identifies `orders-service`; the context identifies `user-0001`. Neither alone grants access to an invoice. Cost: token validation, key rotation, clock handling, and policy lookup. Do not forward broad bearer tokens through every hop.

## 3. Keep databases inside the boundary

A service owns its schema and write credentials. Other services call its contract or consume a minimal event.

```sql
-- Vulnerable: both services can write billing.invoice.
GRANT SELECT, INSERT, UPDATE, DELETE ON billing.invoice TO shared_app;

-- Fixed: billing owns writes; reporting receives only a bounded read surface.
GRANT SELECT, INSERT, UPDATE, DELETE ON billing.invoice TO billing_writer;
GRANT SELECT ON billing.invoice_summary TO reporting_reader;
```

Security: a shared DB bypasses service authorization and defeats compartmentalization (A01/A06, ASVS V8/V15, CWE-653). Cost: calls add latency; event copies add storage and consistency lag. Keep ownership worth that cost. If two modules need one atomic transaction, they may not be separate services yet.

## 4. Treat mTLS as transport, not policy

Validate peer certificates, identities, audiences, and rotation. Then apply endpoint and object policy.

```python
# Runnable policy core; the TLS terminator supplies verified_peer.
from dataclasses import dataclass
@dataclass(frozen=True)
class Request: verified_peer: str; subject: str; tenant: str; object_tenant: str
def allowed(r: Request) -> bool:
    return (r.verified_peer == "orders-service" and r.subject != "" and
            r.tenant == r.object_tenant)
print(allowed(Request("orders-service", "user-0001", "tenant-0001", "tenant-0001")))
```

Security: encryption and peer authentication do not establish per-object permission (ASVS V12 versus V8). Cost: certificate issuance, sidecar or library memory, handshakes, connections, and rotation failures. Measure handshake rate and certificate-expiry errors.

## 5. Constrain service discovery and outbound destinations

Never concatenate user input into a discovery name or URL. Resolve a logical dependency through a static allow-list, require HTTPS, reject credentials and fragments, validate every redirect, and apply network egress controls.

```python
from urllib.parse import urlparse
SERVICES = {"catalog": "https://catalog.service.invalid", "billing": "https://billing.service.invalid"}
def destination(name: str) -> str:
    if name not in SERVICES: raise ValueError("unknown dependency")
    u = urlparse(SERVICES[name])
    if u.scheme != "https" or u.username or u.password or u.fragment: raise ValueError("invalid target")
    return u.geturl()
print(destination("catalog"))
```

Security: an allow-listed logical dependency prevents discovery-mediated SSRF (A01/A06, ASVS V4/V15, CWE-918). DNS and redirects still need runtime enforcement. Cost: allow-list maintenance and reduced dynamic routing flexibility.

## 6. Re-authorize events

A broker ACL authenticates a producer. A signature proves origin and integrity. Neither proves that the producer may cause this consumer to mutate this object.

```typescript
interface Event { type: "invoice.payment_requested"; invoiceId: string; actorId: string }
const invoices = new Map([["invoice-0001", { tenant: "tenant-0001", amount: 1200 }]]);
const actors = new Map([["user-0001", { tenant: "tenant-0001", mayPay: true }]]);
function handle(e: Event): void {
  const actor = actors.get(e.actorId), invoice = invoices.get(e.invoiceId);
  if (!actor?.mayPay || !invoice || actor.tenant !== invoice.tenant) throw new Error("forbidden");
  console.log("pay", invoice.amount);
}
handle({ type: "invoice.payment_requested", invoiceId: "invoice-0001", actorId: "user-0001" });
```

Security: the consumer resolves current authority and does not accept amount, role, or tenant from the event (A01/A08, ASVS V8/V15, CWE-602). Cost: reads per event and duplicate-delivery handling. Add an idempotency store with a bounded retention window.

## 7. Budget connections by replica

Total possible connections are not the pool size in one process.

```go
package main
import "fmt"
func main(){ replicas,deps,pool:=12,5,20; total:=replicas*deps*pool; fmt.Printf("upper bound=%d connections\n",total) }
```

Set per-dependency pools from database/proxy capacity divided by maximum replicas, with headroom for migrations and operators. Bound idle lifetime and wait time. Security: pool exhaustion is an availability boundary (A10, CWE-770). Cost: pools improve reuse but reserve sockets and server memory even when idle.

## 8. Stop retry storms and fan-out amplification

One request that fans out to eight dependencies and retries twice can attempt 24 calls. Retries must fit the original deadline, be limited to safe/idempotent operations, use jitter, and consume a shared retry budget.

```python
import random, time
def call_with_budget(operation, attempts=3, deadline_seconds=0.4):
    end = time.monotonic() + deadline_seconds
    for attempt in range(attempts):
        try: return operation()
        except TimeoutError:
            if attempt + 1 == attempts or time.monotonic() >= end: raise
            time.sleep(min(0.02 * 2**attempt + random.random() * 0.01, max(0, end-time.monotonic())))
```

Security: bounded frequency limits self-inflicted denial of service (A10, CWE-799/CWE-400). Cost: retries spend latency and capacity; hedging spends extra calls. Expose attempts, retry budget consumed, and fan-out width.

## 9. Bound queues, saga state, traces, breakers, and caches

| State | Required bound | Observable |
|---|---|---|
| Queue | item/byte capacity, max age, DLQ retention | depth, oldest age, ingress/egress |
| Saga | expiry, maximum steps and context bytes | active count, oldest age, compensation failures |
| Trace | sampling and attribute length/cardinality | spans/request, dropped spans, exporter queue |
| Breaker | approved destination-key count and eviction | breaker instances, state, key count |
| Cache | entries/bytes, TTL, tenant-safe key | hit rate, size, evictions, stale-policy window |

Security: caller-controlled keys must not allocate durable state without limits (A06/A10, CWE-770/CWE-772). Cost: tight limits reject or evict legitimate work. Size from measured arrival rate and recovery time, then load-test the failure path.

## 10. Keep migration reversible

1. Publish the new contract and API inventory entry.
2. Add traces and reconciliation before moving traffic.
3. Shadow reads without side effects.
4. Backfill in bounded batches with checkpoints.
5. Route a small cohort to the new owner.
6. Stop automatically on authorization-denial, error, latency, divergence, queue-age, or pool-wait thresholds.
7. Roll back routing while retaining accepted writes for reconciliation.
8. Remove compatibility code only after the rollback and retention windows close.

Security: migration paths often bypass normal policy and duplicate sensitive data (A01/A06, ASVS V8/V14/V15). Cost: temporary storage, double reads, trace volume, and operator load. Never let an unbounded dual-write become the permanent architecture.
