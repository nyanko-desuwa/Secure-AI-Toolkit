# Logging and Audit Examples

Eight vulnerable/fixed pairs. Each is specific to logging as a control or logging as a risk.
Every fix says why it closes the hole rather than merely looking cleaner.

## Contents

- [Forged admin action through log injection](#forged-admin-action-through-log-injection) — A09, CWE-117
- [Bearer token leaked into a log line](#bearer-token-leaked-into-a-log-line) — A09, CWE-532
- [Missing authorization-denial event](#missing-authorization-denial-event) — A09, CWE-778
- [Audit event records actor but not target](#audit-event-records-actor-but-not-target) — A09, CWE-223
- [Privileged application can erase the trail](#privileged-application-can-erase-the-trail) — A09
- [Alert rule with no emitter](#alert-rule-with-no-emitter) — A09, CWE-778
- [Timestamp without a timezone](#timestamp-without-a-timezone) — A09, CWE-223
- [Log sink blocks the request path](#log-sink-blocks-the-request-path) — A10, CWE-400

---

## Forged admin action through log injection

`A09:2025` · ASVS 16.4.1 · `CWE-117`

```python
# Vulnerable: username is allowed to create a second line
logger.warning("login failed for username=%s", request.json["username"])
```

The attacker submits:

```text
mallory
2026-07-28T10:00:00Z INFO authz_admin actor=system action=role.grant target=mallory outcome=success
```

The output is two records. The second says the system granted an admin role. An investigator
cannot distinguish it from a real action, and any detector that keys on `authz_admin` may fire
on attacker-written content.

```python
# Fixed: a real JSON encoder keeps the newline inside one field
import structlog

log = structlog.get_logger()
log.warning(
    "authn_login_fail",
    actor=request.json["username"][:128],
    action="session.create",
    target="account",
    outcome="denied",
    source_ip=request.remote_addr,
    request_id=g.request_id,
    user_agent=request.headers.get("User-Agent", "")[:256],
)
```

Why this works: `JSONRenderer` encodes the newline as `\n` inside the actor string. It cannot
become a record boundary. The length cap prevents one value from swallowing a size-limited
record.

The tempting wrong fix is `username.replace("\n", "")`. It leaves carriage return, ANSI ESC,
backspace, and NUL, all of which can alter a line-oriented viewer. Use structured encoding; if
a legacy line sink is unavoidable, remove the entire control-character range.

---

## Bearer token leaked into a log line

`A09:2025` · ASVS 16.2.5 · `CWE-532`

```typescript
// Vulnerable: pino serializes every header, including the usable credential
logger.info({ event: "request_received", headers: req.headers });
```

Every person and vendor with log access can replay the token until expiry. Sink redaction is
too late: the token already crossed the logger, queue, shipper, retry buffer, and possibly a
local fallback file.

```typescript
// Fixed: named fields plus logger-boundary redaction as a backstop
import pino from "pino";

const logger = pino({
  redact: {
    paths: ["*.authorization", "*.cookie", "*.token", "*.password"],
    censor: "[REDACTED]",
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

logger.info({
  event: "request_received",
  request_id: req.id,
  source_ip: req.ip,
  method: req.method,
  path: req.route.path,
  user_agent: req.get("user-agent")?.slice(0, 256),
});
```

Why this works: the token is never passed to the logger. Redaction remains a second layer for
a future careless field, but no downstream component receives the current credential.

---

## Missing authorization-denial event

`A09:2025` · ASVS 16.3.2 · `CWE-778`

```java
// Vulnerable: enforcement works, detection does not
public Invoice readInvoice(User actor, String id) {
    Invoice invoice = repository.findById(id).orElseThrow(NotFoundException::new);
    if (!invoice.ownerId().equals(actor.id())) {
        throw new NotFoundException();
    }
    return invoice;
}
```

An authenticated user can enumerate a thousand invoice IDs. The API returns 404 each time,
but the application emits nothing. Infrastructure logs know only the status, not the actor,
target, or policy reason.

```java
// Fixed: denial emitted at the point that still has the security context
public Invoice readInvoice(User actor, String id, RequestContext ctx) {
    Invoice invoice = repository.findById(id).orElseThrow(NotFoundException::new);
    if (!invoice.ownerId().equals(actor.id())) {
        log.atWarn()
            .addKeyValue("event", "authz_fail")
            .addKeyValue("actor", actor.id())
            .addKeyValue("action", "invoice.read")
            .addKeyValue("target_type", "invoice")
            .addKeyValue("target_id", id)
            .addKeyValue("outcome", "denied")
            .addKeyValue("request_id", ctx.requestId())
            .addKeyValue("source_ip", ctx.sourceIp())
            .log("authorization denied");
        throw new NotFoundException();
    }
    return invoice;
}
```

Why this works: the same branch that enforces the denial emits the event, so no separate code
path can drift. `actor` and `target_id` let the SIEM detect one actor walking many IDs.

The log is not the authorization control. Removing the `throw` would still leak the invoice.
Tests must assert both the 404 and the event.

---

## Audit event records actor but not target

`A09:2025` · ASVS 16.2.1 · `CWE-223`

```sql
-- Vulnerable: non-reconstructable audit event
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL
);

INSERT INTO audit_log (occurred_at, actor_id, action)
VALUES (now(), 'admin-7', 'customer.delete');
```

The record proves `admin-7` deleted a customer but not which customer. During an incident it
cannot answer blast radius, and a subject-access request cannot find the affected record.

```sql
-- Fixed: the target and outcome are required, not optional prose
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    request_id TEXT,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb
);

INSERT INTO audit_log
    (actor_id, action, target_type, target_id, outcome, request_id)
VALUES
    ('admin-7', 'customer.delete', 'customer', 'cust-4192', 'success', 'req-01J3Y8');
```

Why this works: non-null target columns make an incomplete audit row impossible to insert.
The fix is a storage invariant, not a convention the next call site can forget.

Do not put the customer's name, email, or deleted row into `detail`. The opaque ID is enough
to correlate without turning the audit store into a PII archive.

---

## Privileged application can erase the trail

`A09:2025` · ASVS 16.4.2, 16.4.3

```sql
-- Vulnerable: compromised application owns the evidence against itself
GRANT ALL PRIVILEGES ON audit_log TO app_user;
```

After granting an admin role, an attacker with the service account runs
`DELETE FROM audit_log WHERE action = 'role.grant'`. The table remains valid and gives no
sign that history changed.

```sql
-- Fixed: append-only application principal
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM app_user;
GRANT INSERT ON audit_log TO app_user;
GRANT SELECT ON audit_log TO audit_reader;
```

Ship each entry to a logically separate account or append-only object store. Hash-chain the
rows and periodically anchor the current head hash outside the database.

Why this works: the compromised application role cannot alter or delete prior rows, and the
external copy survives a breach of its trust domain. The external anchor is essential to the
claim: a full database writer can recompute an unanchored hash chain, so chaining alone is not
fully tamper-evident.

---

## Alert rule with no emitter

`A09:2025` · ASVS 16.3.3 · `CWE-778`

The detection repository contains:

```text
# Vulnerable: correct query, nonexistent event
alert "admin role granted"
when event = privilege_permissions_changed and to_role = "admin"
```

The application contains:

```python
def set_role(actor, target, role):
    target.role = role
    db.commit()
    logger.info("role updated for %s", target.id)
```

The rule never fires because no event has the name or fields it queries. The SOC sees a green
dashboard and assumes role grants are covered.

```python
# Fixed: emitter and rule share a tested contract
def set_role(actor, target, role):
    old_role = target.role
    target.role = role
    db.commit()
    log.warning(
        "privilege_permissions_changed",
        actor=actor.id,
        action="user.role.change",
        target_type="user",
        target_id=target.id,
        from_role=old_role,
        to_role=role,
        outcome="success",
        request_id=current_request_id(),
    )

def test_admin_grant_emits_detection_event(caplog):
    set_role(admin, user, "admin")
    event = next(json.loads(r.message) for r in caplog.records)
    assert event["event"] == "privilege_permissions_changed"
    assert event["to_role"] == "admin"
```

Why this works: the test couples the domain action to the exact schema the alert reads. A
rename now fails CI instead of silently reducing the rule's results to zero.

---

## Timestamp without a timezone

`A09:2025` · ASVS 16.2.2 · `CWE-223`

```go
// Vulnerable: local wall time loses the offset
logger.Info("authn_login_success",
    "actor", actorID,
    "timestamp", time.Now().Format("2006-01-02 15:04:05"),
)
```

`2026-11-01 01:30:00` occurs twice during a daylight-saving fall-back in many regions. A
second service in UTC produces a different order for the same request. Impossible-travel and
cross-service timelines become guesses, and the offset cannot be recovered later.

```go
// Fixed: UTC instant with RFC 3339 offset marker
logger.Info("authn_login_success",
    "actor", actorID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

Why this works: RFC 3339 preserves an unambiguous instant (`Z` means UTC), so every service
sorts the same event in the same position. Synchronise the hosts too; formatting a wrong clock
in UTC does not make it accurate.

---

## Log sink blocks the request path

`A10:2025` · ASVS 16.5.2, 16.5.3 · `CWE-400`

```python
# Vulnerable: SIEM latency is customer latency; outage is an easy DoS
@app.post("/orders")
def create_order():
    order = save_order(request.json)
    requests.post(SIEM_URL, json={"event": "order_created", "id": order.id}, timeout=30)
    return order
```

An unavailable sink holds one worker for 30 seconds per request. The request may time out
after the order commits, so the client retries and creates a duplicate. Developers under
pressure disable logging, creating an A09 failure as well.

```python
# Fixed: bounded asynchronous queue for application logs
import queue

log_queue = queue.Queue(maxsize=10_000)

def emit_app_event(event):
    try:
        log_queue.put_nowait(event)
    except queue.Full:
        metrics.increment("logging.events_dropped", tags={"event": event["event"]})

@app.post("/orders")
def create_order():
    order = save_order(request.json)
    emit_app_event({"event": "order_created", "target_id": str(order.id)})
    return order
```

Why this works: the queue bounds memory and removes remote I/O from the request. A dropped
event is visible through a metric and a deadman alert instead of becoming an outage or silent
loss.

Honest limitation: this pattern is not appropriate for a must-not-lose audit event. That row
must commit in the same database transaction as the order, so business state and evidence
cannot diverge. Application logs and audit trails have different failure semantics.

---

## Sources

- OWASP Top 10 2025 A09 — <https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
- OWASP ASVS 5.0 V16 — <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>
- OWASP Logging Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- CWE-117 — <https://cwe.mitre.org/data/definitions/117.html>
- CWE-532 — <https://cwe.mitre.org/data/definitions/532.html>
- CWE-778 — <https://cwe.mitre.org/data/definitions/778.html>
