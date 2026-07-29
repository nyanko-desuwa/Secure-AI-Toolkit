# Event-Driven Examples

Eight before/after pairs. Each names the hazard from [SKILL.md](../SKILL.md), the security
mapping, the runtime cost, and the residual gap. Every block is a complete script. TypeScript
examples run with `npm install zod tsx` and `npx tsx file.ts`. Python examples use Python 3.11;
the schema example also needs `pip install pydantic`.

Do not copy a block labelled `Vulnerable:`.

## Contents

- [Consumer trusts a role from the payload](#consumer-trusts-a-role-from-the-payload) - E1, A01, CWE-863
- [Full customer row on a retained topic](#full-customer-row-on-a-retained-topic) - E2, A01, CWE-359
- [Message body chooses the Python object](#message-body-chooses-the-python-object) - E3, A08, CWE-502
- [Duplicate delivery charges twice](#duplicate-delivery-charges-twice) - E4, A06, CWE-799
- [Older event overwrites newer state](#older-event-overwrites-newer-state) - E5, A06, CWE-841
- [Poison message retries forever and leaks into logs](#poison-message-retries-forever-and-leaks-into-logs) - E6, A09/A10, CWE-532
- [Subscription retains every client](#subscription-retains-every-client) - E9, A06, CWE-401
- [In-memory bus grows until the process dies](#in-memory-bus-grows-until-the-process-dies) - E9, A06, CWE-770

---

## Consumer trusts a role from the payload

`E1` · `A01:2025` · `CWE-863` · ASVS V8

The publisher chooses the role, the target, and the amount.

```typescript
// Vulnerable: role-vulnerable.ts
interface RefundEvent {
  refundId: string;
  actorRole: "customer" | "finance_admin";
  amountCents: number;
}

async function handle(e: RefundEvent): Promise<void> {
  if (e.actorRole !== "finance_admin") throw new Error("forbidden");
  console.log(`credited ${e.amountCents} for ${e.refundId}`);
}

void handle({ refundId: "refund-0001", actorRole: "finance_admin", amountCents: 50000 });
```

The consumer must re-resolve the actor and load the refund in that actor's tenant.

```typescript
// Fixed: role-fixed.ts
import { z } from "zod";

const Event = z.object({
  eventId: z.string().uuid(),
  refundId: z.string().regex(/^refund-[0-9]{4}$/),
  actorId: z.string().regex(/^user-[0-9]{4}$/),
}).strict();

const actors = new Map([["user-0001", {
  tenantId: "tenant-0001", canApprove: true,
}]]);
const refunds = new Map([["refund-0001", {
  tenantId: "tenant-0001", amountCents: 50000,
}]]);

async function handle(raw: unknown): Promise<void> {
  const event = Event.parse(raw);
  const actor = actors.get(event.actorId);
  if (!actor?.canApprove) throw new Error("forbidden");
  const refund = refunds.get(event.refundId);
  if (!refund || refund.tenantId !== actor.tenantId) throw new Error("not found");
  console.log(`credited ${refund.amountCents} for ${event.refundId}`);
}

void handle({
  eventId: "00000000-0000-4000-8000-000000000001",
  refundId: "refund-0001",
  actorId: "user-0001",
});
```

Why it holds: the contract has no role or amount. The handler can only get them from stores it
controls. Cost: two reads per event. Residual gap: caching the actor makes revocation stale for the
cache TTL.

---

## Full customer row on a retained topic

`E2` · `A01:2025` · `CWE-359` · ASVS V8 / V14

```python
# Vulnerable: customer_vulnerable.py
import json

customer = {
    "id": "customer-0001",
    "email": "person@example.invalid",
    "national_id": "TEST-ID-NOT-REAL",
    "support_notes": "test record",
    "internal_risk_score": 93,
}
print(json.dumps({"type": "customer.updated", "customer": customer}))
```

The analytics subscriber needed the ID. Topic retention and replay now apply to every field.

```python
# Fixed: customer_fixed.py
import json
from datetime import UTC, datetime
from uuid import UUID

message = {
    "type": "customer.updated",
    "event_id": str(UUID("00000000-0000-4000-8000-000000000001")),
    "schema_version": 1,
    "customer_id": "customer-0001",
    "changed_fields": ["email"],
    "occurred_at": datetime.now(UTC).isoformat(),
}
print(json.dumps(message))
```

Why it holds: values are absent. Each consumer fetches through its own authorization. Cost: one
call per relevant event and a race with newer state. Residual gap: historical consumers may need a
fat event; justify each field and restrict its topic.

---

## Message body chooses the Python object

`E3` · `A08:2025` · `CWE-502` · ASVS V15

```python
# Vulnerable: pickle_vulnerable.py
import pickle

body = pickle.dumps({"type": "order.placed", "order_id": "order-0001"})
event = pickle.loads(body)  # the input selects constructors while loading
print(event)
```

A benign test value does not make `pickle.loads` safe for broker input.

```python
# Fixed: schema_fixed.py
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class OrderPlaced(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["order.placed"]
    event_id: UUID
    schema_version: Literal[1]
    order_id: str = Field(pattern=r"^order-[0-9]{4}$", max_length=32)

body = b'{"type":"order.placed","event_id":"00000000-0000-4000-8000-000000000001","schema_version":1,"order_id":"order-0001"}'
if len(body) > 64 * 1024:
    raise ValueError("event too large")
event = OrderPlaced.model_validate_json(body)
print(event.order_id)
```

Why it holds: one declared model can be constructed, and size is bounded before parsing. Cost: a
model per event version. Residual gap: keep the model flat so deeply nested JSON is not an
allocation lever.

---

## Duplicate delivery charges twice

`E4` · `A06:2025` · `CWE-799` · ASVS V2

```python
# Vulnerable: charge_vulnerable.py
balance = 0

def handle(event: dict[str, int | str]) -> None:
    global balance
    balance += int(event["amount_cents"])

message = {"event_id": "event-0001", "amount_cents": 2500}
handle(message)
handle(message)
print(balance)  # 5000: one logical event, two effects
```

```python
# Fixed: charge_fixed.py
import sqlite3

conn = sqlite3.connect(":memory:")
conn.executescript("""
CREATE TABLE processed_event (
    event_id TEXT PRIMARY KEY,
    processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE ledger (
    event_id TEXT PRIMARY KEY,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0)
);
""")

def handle(event_id: str, amount_cents: int) -> None:
    try:
        with conn:
            conn.execute("INSERT INTO processed_event(event_id) VALUES (?)", (event_id,))
            conn.execute("INSERT INTO ledger(event_id, amount_cents) VALUES (?, ?)",
                         (event_id, amount_cents))
    except sqlite3.IntegrityError:
        return

handle("event-0001", 2500)
handle("event-0001", 2500)
print(conn.execute("SELECT SUM(amount_cents) FROM ledger").fetchone()[0])
```

Why it holds: the unique claim and effect share one transaction. Cost: one row per event. Residual
gap: delete by time after a TTL longer than the broker's redelivery window; pass the same key to
external providers.

---

## Older event overwrites newer state

`E5` · `A06:2025` · `CWE-841` · ASVS V2

```python
# Vulnerable: order_vulnerable.py
state = {"version": 0, "status": "created"}
for event in [{"version": 3, "status": "shipped"}, {"version": 2, "status": "paid"}]:
    state.update(event)
print(state)  # version 2: state went backwards
```

```python
# Fixed: order_fixed.py
state = {"version": 0, "status": "created"}
for event in [{"version": 3, "status": "shipped"}, {"version": 2, "status": "paid"}]:
    if event["version"] > state["version"]:
        state = event.copy()
print(state)  # version 3
```

Production uses one conditional update: `WHERE source_version < :new_version`. Why it holds: an
older event cannot satisfy the predicate. Cost: the producer assigns a monotonic version per
entity. Residual gap: per-key partitioning turns a hot entity into a throughput ceiling.

---

## Poison message retries forever and leaks into logs

`E6` · `A09:2025` · `A10:2025` · `CWE-532` · ASVS V16

```python
# Vulnerable: retry_vulnerable.py
import logging

message = {"event_id": "event-0001", "token": "TEST-TOKEN-NOT-REAL"}
try:
    raise ValueError("invalid schema")
except Exception as error:
    logging.error("retry body=%r error=%s", message, error)
    print("requeued with no cap")
```

```python
# Fixed: retry_fixed.py
import logging
from dataclasses import dataclass

@dataclass(frozen=True)
class Message:
    event_id: str
    event_type: str
    body: bytes

class PermanentFailure(Exception):
    pass

def route_failure(message: Message, error: Exception, attempt: int) -> str:
    if isinstance(error, PermanentFailure) or attempt >= 5:
        logging.error("dead-letter id=%s type=%s attempt=%d error=%s",
                      message.event_id, message.event_type, attempt, type(error).__name__)
        return "dead-letter"
    delay = min(2 ** attempt, 60)
    return f"retry in {delay}s"

msg = Message("event-0001", "order.placed", b"TEST-TOKEN-NOT-REAL")
print(route_failure(msg, PermanentFailure("invalid schema"), 1))
```

Why it holds: permanent failure has no retry path, transient failure has a ceiling, and the logger
never receives the body. Cost: the DLQ needs retention, an alert, an owner, and redrive tooling.
Residual gap: the original body remains sensitive inside the DLQ.

---

## Subscription retains every client

`E9` · `A06:2025` · `CWE-401`

```typescript
// Vulnerable: listener-vulnerable.ts
import { EventEmitter } from "node:events";
const bus = new EventEmitter();

function connect(clientId: string): void {
  bus.on("order.updated", (id: string) => console.log(clientId, id));
}
for (let i = 0; i < 100; i += 1) connect(`client-${i}`);
console.log(bus.listenerCount("order.updated")); // 100, retained forever
```

```typescript
// Fixed: listener-fixed.ts
import { EventEmitter } from "node:events";
const bus = new EventEmitter();

function connect(clientId: string): () => void {
  const onUpdate = (id: string): void => console.log(clientId, id);
  bus.on("order.updated", onUpdate);
  return () => bus.off("order.updated", onUpdate);
}
const disconnect = connect("client-0001");
disconnect();
console.log(bus.listenerCount("order.updated")); // 0
```

Why it holds: teardown has the same function reference and is returned with registration. Cost:
every owner must call the disposer on close, error, and abort. Residual gap: an `AbortSignal`-based
wrapper is safer where callers commonly forget cleanup.

---

## In-memory bus grows until the process dies

`E9` · `A06:2025` · `CWE-770` · `CWE-400`

```python
# Vulnerable: queue_vulnerable.py
import asyncio

queue: asyncio.Queue[bytes] = asyncio.Queue()  # maxsize=0 means unbounded
for _ in range(100_000):
    queue.put_nowait(b"x" * 1024)
print(queue.qsize())
```

```python
# Fixed: queue_fixed.py
import asyncio

queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)

async def publish(body: bytes) -> None:
    try:
        await asyncio.wait_for(queue.put(body), timeout=0.050)
    except TimeoutError as error:
        raise RuntimeError("event bus saturated") from error

async def main() -> None:
    await publish(b"order-0001")
    print((await queue.get()).decode())
    queue.task_done()

asyncio.run(main())
```

Why it holds: at most 1000 bodies are retained, and pressure becomes a visible failure after 50
milliseconds. Cost: blocking raises request latency; rejecting needs an explicit caller response.
Residual gap: size 1000 from measured burst rate and handler latency, not from this example.

## Sources

- CWE entries and titles - [cwe-event-driven.md](../references/cwe-event-driven.md)
- OWASP mapping - [owasp-mapping.md](../references/owasp-mapping.md)
- Broker limits - [broker-controls.md](../references/broker-controls.md)
