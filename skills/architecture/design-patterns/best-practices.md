# Design Patterns Best Practices

Each pattern below earns its cost only when it creates a real boundary or removes measured coupling.
The code is intentionally small but runnable in the stated language/runtime.

## Strategy: policy-selected behavior

Use Strategy when algorithms vary independently and the caller must not know their concrete types.
Do not use it for a stable three-case switch in one function.

```typescript
// Vulnerable: a request selects a privileged function by name.
type Strategy = (amount: number) => number;
const strategies: Record<string, Strategy> = {
  waive: () => 0,
  standard: (n) => n,
};
export function quote(raw: { strategy: string; amount: number }): number {
  return strategies[raw.strategy](raw.amount);
}
```

The lookup is not an authorization policy. A client-selected `waive` path can change billing.
This is A01/A06, ASVS V8/V15, and CWE-602 when the client is trusted to enforce policy.

```typescript
// Fixed: the server derives the allowed algorithm from an authenticated actor.
type Actor = { canWaive: boolean };
type QuoteStrategy = { quote(amount: number): number };
const standard: QuoteStrategy = { quote: (n) => n };
const waiver: QuoteStrategy = { quote: () => 0 };
function choose(actor: Actor): QuoteStrategy {
  return actor.canWaive ? waiver : standard;
}
export function quote(actor: Actor, amount: number): number {
  if (!Number.isFinite(amount) || amount < 0) throw new Error("invalid_amount");
  return choose(actor).quote(amount);
}
```

Security: selection is server-owned and validation precedes behavior. Cost: one dispatch and one
strategy object; a registry adds lookup and testing overhead. Keep the registry closed and small.

## Adapter: contain an external contract

Use Adapter when an external API, legacy model, or error vocabulary would otherwise spread through
the domain. Do not use it to hide a dependency that every caller still imports directly.

```python
# Vulnerable: domain code trusts provider fields and exceptions.
def charge(provider, cents, token):
    return provider.create_payment(amount=cents, source=token)["id"]
```

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Receipt:
    reference: str

class PaymentError(Exception):
    pass

class PaymentGateway:
    def __init__(self, provider):
        self._provider = provider

    def charge(self, cents: int, token: str) -> Receipt:
        if cents <= 0 or cents > 1_000_000:
            raise ValueError("amount_out_of_range")
        if not token or len(token) > 256:
            raise ValueError("invalid_token_reference")
        try:
            result = self._provider.create_payment(amount=cents, source=token)
            reference = result.get("id")
            if not isinstance(reference, str) or not reference:
                raise PaymentError("provider_contract_error")
            return Receipt(reference)
        except PaymentError:
            raise
        except Exception as exc:
            raise PaymentError("provider_unavailable") from exc
```

Security: external fields are allowlisted and provider details do not cross the boundary. Cost:
translation allocates a value object and can obscure provider-specific retry semantics. Preserve
causes for logs, but return a stable error vocabulary to callers. Parameterize any adapter query.

## Factory: enforce construction invariants

Use a Factory when callers currently construct objects with different tenant, key, timeout, or
policy settings. Do not use it as a service locator that can return arbitrary services.

```typescript
// Vulnerable: callers can create an unscoped repository.
class InvoiceRepository {
  constructor(private readonly db: { query(sql: string): Promise<unknown[]> }, private tenant?: string) {}
}
export function makeRepository(db: any, raw: any) {
  return new InvoiceRepository(db, raw.tenantId);
}
```

```typescript
type Database = { query(sql: string, params: unknown[]): Promise<unknown[]> };

class ScopedInvoiceRepository {
  constructor(
    private readonly db: Database,
    private readonly tenantId: string,
  ) {}
  recent(limit: number) {
    const capped = Math.min(Math.max(Math.trunc(limit), 1), 200);
    return this.db.query(
      "SELECT id, number FROM invoice WHERE tenant_id = $1 ORDER BY id LIMIT $2",
      [this.tenantId, capped],
    );
  }
}
export function createInvoiceRepository(
  db: Database, actor: { tenantId: string },
): ScopedInvoiceRepository {
  if (!actor.tenantId) throw new Error("missing_tenant");
  return new ScopedInvoiceRepository(db, actor.tenantId);
}
```

Security: the factory derives scope and makes an unscoped instance impossible through its public
API. This addresses A01, ASVS V8, and CWE-1220. Cost: construction is centralized and tests need a
factory or a narrow fake. Keep the concrete class private to the module when it is the boundary.

## Decorator: enforce cross-cutting controls

Use a Decorator when every operation on a narrow interface needs the same timeout, authorization,
audit, or rate budget. Do not use one if callers can freely obtain the wrapped implementation.

```typescript
type Reader = { get(tenantId: string, id: string): Promise<string | null> };
type Actor = { tenantId: string; canRead: boolean };

function authorized(reader: Reader, actor: Actor): Reader {
  return {
    async get(tenantId, id) {
      if (!actor.canRead || tenantId !== actor.tenantId) throw new Error("forbidden");
      return reader.get(tenantId, id);
    },
  };
}
```

Security: the decorator checks both identity and capability at the call boundary. Cost: an extra
call frame and risk of duplicate or missing wrapping. Register only the decorated interface in DI;
never export the concrete implementation as an alternate path. A bypass is A01/CWE-653.

## Observer: independent notification

Use Observer when consumers are genuinely independent and delayed delivery is acceptable. Do not
use it to enforce an invariant, sequence a transaction, or hide business-critical call order.

```typescript
import { EventEmitter } from "node:events";

type Changed = { id: string; value: string };
const bus = new EventEmitter();

export function subscribe(handler: (event: Changed) => void): () => void {
  bus.on("changed", handler);
  return () => bus.off("changed", handler);
}
export function publish(event: Changed): void { bus.emit("changed", event); }
```

The returned teardown is the boundary. Without it, a request callback retains request data for the
publisher lifetime: CWE-401/772 and A10 on error or disconnect. Cost: retained listeners, ordering
ambiguity, synchronous callback latency, and no transaction. Use a bounded async queue and an
explicit delivery contract when consumers can be slow.

## Singleton and process scope

Use a singleton only for immutable configuration or a process-owned, stateless resource manager.
Never store current actor, tenant, request, response, transaction, or mutable permission state in it.

```python
# Vulnerable: a process singleton captures the last request's tenant.
class Context:
    tenant = None
context = Context()

def handle(request):
    context.tenant = request.tenant
    return load_invoices(context.tenant)
```

```python
from contextvars import ContextVar

_current_tenant: ContextVar[str] = ContextVar("tenant")

def handle(request):
    token = _current_tenant.set(request.tenant)
    try:
        return load_invoices(_current_tenant.get())
    finally:
        _current_tenant.reset(token)
```

Security: the context cannot bleed into a pooled worker's next request when reset in `finally`.
A01, ASVS V8, and CWE-401 apply to the vulnerable form. Cost: context lookup and lifecycle
complexity. Prefer explicit parameters when practical; context propagation must be bounded and
observable.

## Repository: intent-scoped persistence

Use a Repository when it removes raw storage access from domain code and can express authorization
in its required methods. Do not use a generic `get(id)` repository that erases tenant or business
intent.

```python
class InvoiceReader:
    def __init__(self, db):
        self.db = db

    def by_id(self, tenant_id: str, invoice_id: str):
        return self.db.fetch_one(
            "SELECT id, number, total FROM invoice WHERE tenant_id = %s AND id = %s",
            (tenant_id, invoice_id),
        )
```

Security: the scope is explicit and the selected fields are narrow. Cost: mapping layer and risk
of N+1 queries if each aggregate loads relations separately. Add query-count tests and batch or
join deliberately. A raw query path beside the repository defeats CWE-653 compartmentalization.

## Object pool and bounded queue

Use a pool only when setup cost is measured and reuse is safe after reset. Do not pool mutable
request objects, security contexts, or objects with unknown cleanup.

```python
from contextlib import contextmanager
from queue import Queue, Full, Empty

class Pool:
    def __init__(self, items):
        items = list(items)
        if not items:
            raise ValueError("pool_requires_items")
        self._items = Queue(maxsize=len(items))
        for item in items:
            self._items.put_nowait(item)

    @contextmanager
    def lease(self, timeout=1.0):
        try:
            item = self._items.get(timeout=timeout)
        except Empty as exc:
            raise TimeoutError("pool_exhausted") from exc
        try:
            yield item
        finally:
            reset(item)
            try:
                self._items.put_nowait(item)
            except Full:
                close(item)
```

The example makes capacity, wait time, reset, and disposal explicit. Bound callers before they enter
the pool with a semaphore, bounded executor, or bounded request queue; pool capacity alone does not
bound waiting request state. Ensure a lease cannot be returned twice and that cancellation releases
it. Missing release is CWE-772; an unlimited waiter queue or object allocation is CWE-770. Cost:
contention and contamination risk; measure reuse before adding it.
