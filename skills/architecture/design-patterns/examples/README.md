# Design Patterns Examples

Seven before/after pairs. Each pair uses concrete TypeScript or Python and names the boundary,
security implication, lifecycle cost, and residual gap. Run TypeScript with a current Node runtime
and Python with Python 3.11+ where `ContextVar` examples are used.

## Contents

- [Untrusted strategy selection](#untrusted-strategy-selection) — A01/A06, CWE-602
- [Repository without tenant scope](#repository-without-tenant-scope) — A01, CWE-1220
- [Decorator bypass](#decorator-bypass) — A01/A06, CWE-653
- [Adapter swallowing failures](#adapter-swallowing-failures) — A10
- [Observer listener leak](#observer-listener-leak) — A06/A10, CWE-401/772
- [Singleton request state](#singleton-request-state) — A01/A06, CWE-401
- [Pool and queue growth](#pool-and-queue-growth) — A06/A10, CWE-770/772

---

## Untrusted strategy selection

A client-selected strategy must not grant a privileged operation.

```typescript
// Vulnerable: raw input selects a waiver algorithm.
type Rule = (cents: number) => number;
const rules: Record<string, Rule> = {
  normal: (n) => n,
  waive: () => 0,
};
export function price(raw: { rule: string; cents: number }): number {
  return rules[raw.rule](raw.cents);
}
console.log(price({ rule: "waive", cents: 500 }));
```

The request controls capability, not merely representation. This is A01/A06, ASVS V8/V15, and
CWE-602 where the client-side choice is treated as enforcement.

```typescript
// Fixed: capability comes from authenticated server-side policy.
type Actor = { mayWaive: boolean };
const normal = (n: number) => n;
const waiver = () => 0;
export function price(actor: Actor, cents: number): number {
  if (!Number.isSafeInteger(cents) || cents < 0) throw new Error("invalid_amount");
  return (actor.mayWaive ? waiver : normal)(cents);
}
console.log(price({ mayWaive: false }, 500)); // 500
```

The boundary is the actor policy, not the registry. Cost: one dispatch and a closed registry.
Residual gap: the policy source and actor authentication are outside this example and must be
verified in the application.

---

## Repository without tenant scope

A generic `get(id)` lets callers forget the security boundary.

```python
# Vulnerable: the repository can read any tenant's row.
class InvoiceRepository:
    def __init__(self, db): self.db = db
    def get(self, invoice_id):
        return self.db.fetch_one("SELECT id, number FROM invoice WHERE id = %s", (invoice_id,))
```

```python
# Fixed: tenant is required and is part of the query predicate.
class InvoiceReader:
    def __init__(self, db): self.db = db
    def by_id(self, tenant_id: str, invoice_id: str):
        if not tenant_id or not invoice_id:
            raise ValueError("missing_scope")
        return self.db.fetch_one(
            "SELECT id, number FROM invoice WHERE tenant_id = %s AND id = %s",
            (tenant_id, invoice_id),
        )
```

The method signature and SQL jointly make scope explicit. Cite A01, ASVS V8, and CWE-1220 when a
cross-tenant read is possible. Cost: more explicit methods and a mapping layer; batch related reads
to avoid N+1 queries. Residual gap: database-level row security is still valuable where raw access
exists.

---

## Decorator bypass

A decorator does not protect a concrete class that callers can construct directly.

```typescript
// Vulnerable: a controller can bypass the policy by constructing SqlReader.
class SqlReader {
  async get(id: string): Promise<string> { return `row:${id}`; }
}
class AuthorizedReader {
  constructor(private readonly inner: SqlReader, private readonly allowed: boolean) {}
  get(id: string) { if (!this.allowed) throw new Error("forbidden"); return this.inner.get(id); }
}
export const direct = new SqlReader(); // bypass
```

```typescript
// Fixed: compose privately and export only the policy-bearing interface.
interface Reader { get(id: string): Promise<string>; }
class SqlReader implements Reader {
  async get(id: string) { return `row:${id}`; }
}
function authorized(inner: Reader, allowed: boolean): Reader {
  return { get: async (id) => {
    if (!allowed) throw new Error("forbidden");
    return inner.get(id);
  }};
}
export function createReader(actor: { canRead: boolean }): Reader {
  return authorized(new SqlReader(), actor.canRead);
}
console.log(await createReader({ canRead: true }).get("invoice-1"));
```

The concrete type is module-private in the supported composition path. This removes a representable
bypass: A01/A06, ASVS V8/V15, CWE-653. Cost: one wrapper call and a composition function. Residual
gap: reflection, test-only exports, or another module may still bypass it; search registrations.

---

## Adapter swallowing failures

An adapter that returns a default turns dependency failure into false business state.

```python
# Vulnerable: an outage becomes a valid zero balance.
def balance(provider, account_id):
    try:
        return provider.fetch(account_id)["balance"]
    except Exception:
        return 0
```

```python
# Fixed: validate and translate without fabricating success.
class ProviderUnavailable(Exception): pass
class ProviderContractError(Exception): pass

def balance(provider, account_id: str) -> int:
    if not account_id: raise ValueError("missing_account")
    try:
        result = provider.fetch(account_id)
    except Exception as exc:
        raise ProviderUnavailable("balance_unavailable") from exc
    value = result.get("balance") if isinstance(result, dict) else None
    if not isinstance(value, int) or value < 0:
        raise ProviderContractError("invalid_balance_response")
    return value
```

The adapter boundary has a stable error vocabulary and no provider internals in the result. A10 and
ASVS V16 apply when the vulnerable form hides an exceptional condition. Cost: validation and error
translation. Residual gap: retry and timeout policy must be owned by the application, not guessed in
the adapter.

---

## Observer listener leak

A listener that captures a response survives after the request unless the owner removes it.

```typescript
import { EventEmitter } from "node:events";
const bus = new EventEmitter();

type Response = { write(value: string): void };
// Vulnerable: no cleanup; every call retains response forever.
export function attach(response: Response, tenant: string): void {
  bus.on("changed", (event: { tenant: string }) => {
    if (event.tenant === tenant) response.write("changed");
  });
}
```

```typescript
// Fixed: return the lifecycle operation and use the same callback reference.
export function attachSafe(response: Response, tenant: string): () => void {
  const handler = (event: { tenant: string }) => {
    if (event.tenant === tenant) response.write("changed");
  };
  bus.on("changed", handler);
  return () => bus.off("changed", handler);
}
const remove = attachSafe({ write: console.log }, "tenant-a");
remove();
```

The publisher no longer retains the request closure after `remove`. This is A06/A10, ASVS V16,
and CWE-401/772. Cost: a teardown call and synchronous callback work. Residual gap: production code
must call teardown on close, error, cancellation, and timeout; this local example cannot prove that.

---

## Singleton request state

Process-scoped mutable state can expose one tenant to the next request.

```python
# Vulnerable: pooled workers reuse the previous tenant.
class RequestState: tenant = None
state = RequestState()
def handle(request):
    state.tenant = request.tenant
    return load_invoices(state.tenant)
```

```python
from contextvars import ContextVar

tenant_scope: ContextVar[str] = ContextVar("tenant_scope")
def handle_safe(request):
    token = tenant_scope.set(request.tenant)
    try:
        return load_invoices(tenant_scope.get())
    finally:
        tenant_scope.reset(token)
```

Explicitly passing `request.tenant` is simpler when call depth permits. If context-local state is
needed, resetting in `finally` prevents stale identity. A01/A06, ASVS V8/V15, and CWE-401 apply to
the vulnerable form. Cost: context lookup and disciplined scope. Residual gap: background work must
not inherit request context without a deliberate ownership and cancellation policy.

---

## Pool and queue growth

A pool can be bounded while its waiting work is not, and a lease can be retained after failure.

```python
# Vulnerable: unlimited waiters and no guaranteed release.
from queue import Queue
pool = Queue()
for _ in range(2): pool.put(object())
def work(fn):
    item = pool.get()                 # waits forever; callers accumulate
    result = fn(item)                 # exception loses the lease
    pool.put(item)
    return result
```

```python
from queue import Queue, Empty, Full

pool = Queue(maxsize=2)
for _ in range(2): pool.put(object())
waiters = Queue(maxsize=10)

def work(fn, timeout=0.5):
    try:
        waiters.put_nowait(True)
    except Full as exc:
        raise RuntimeError("busy") from exc
    try:
        item = pool.get(timeout=timeout)
        try:
            return fn(item)
        finally:
            reset(item)
            pool.put_nowait(item)
    except Empty as exc:
        raise TimeoutError("pool_exhausted") from exc
    finally:
        waiters.get_nowait()
        waiters.task_done()

def reset(_item):
    pass

print(work(lambda _: "ok"))
```

The fixed version bounds waiters, times acquisition, and returns the lease on function failure.
Missing release is CWE-772; missing allocation or queue limits are CWE-770, A06/A10, ASVS V15/V16.
Cost: saturation becomes an observable error and callers must retry or shed work. Residual gap:
`reset` must clear every mutable field before reuse; pooling request/security objects is usually
unsafe.

---

## When not to use a pattern

A settings screen with one implementation, one database, and the same read/write shape does not
need Strategy, Factory, Observer, Repository, and Decorator folders. Use explicit functions and a
scoped data-access call. Add a pattern only when a measured variation or an enforceable boundary
appears. The absence of ceremony is a valid architectural result.
