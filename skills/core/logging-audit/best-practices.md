# Logging Best Practices

Patterns that survive an incident review. Each names its Top 10 category, ASVS requirement,
and CWE where one applies.

## Required fields

`A09:2025` · ASVS 16.2.1 · `CWE-223`

An entry that says "access denied" is worse than no entry: it consumes storage and answers
nothing. Every security event carries eight fields.

| Field | Why |
|---|---|
| `actor` | Stable user or service ID from the session, never from the request body |
| `action` | Machine event name, e.g. `authz_fail` |
| `target` | Type and ID of the object acted on |
| `outcome` | `success` / `denied` / `error`. Not implied by log level |
| `timestamp` | ISO 8601, UTC or explicit offset (ASVS 16.2.2) |
| `source_ip` | Client IP, resolved through the proxy chain you trust |
| `request_id` | Correlation across services |
| `user_agent` | Cheap fingerprint that separates a browser from a scraper |

```python
# Vulnerable: no actor, no target, no outcome. Unusable in an investigation
logger.warning("access denied")

# Fixed: structlog with an explicit field set
log.warning(
    "authz_fail",
    actor=actor.id,
    action="invoice.read",
    target_type="invoice",
    target_id=invoice_id,
    outcome="denied",
    reason="not_owner",
    source_ip=request.remote_addr,
    request_id=g.request_id,
    user_agent=request.headers.get("User-Agent", "")[:256],
)
```

The fix works because each field is a queryable dimension. `group by actor` and
`distinct(target_id)` are what turn the entry into the enumeration detection in
[references/detection-rules.md](references/detection-rules.md#repeated-authorization-denial).
The free-text version supports neither.

Truncate the user agent. It is attacker-controlled and unbounded.

## What to log

`A09:2025` · ASVS 16.3.1, 16.3.2, 16.3.3, 16.3.4

| Event | Requirement |
|---|---|
| Authentication success and failure, with factors used | 16.3.1 |
| Authorization denials. All authorization decisions at L3 | 16.3.2 |
| Privilege and role changes, including self-service ones | 16.3.2 |
| Admin actions: impersonation, config change, user deletion | 16.3.3 |
| Data exports, with the row count | 16.3.2 (L3) |
| Secret access: which secret name, by which principal | 16.3.2 |
| Configuration changes, with old and new values | 16.3.3 |
| Security control bypass attempts: validation, business logic, rate limit | 16.3.3 |
| Unexpected errors and control failures, e.g. backend TLS failure | 16.3.4 |

Logging only successful logins is the example OWASP names in A09. Failures are where the
attack is.

Two asymmetries to get right. Log the secret's name, never its value. Log the export's row
count, not its contents.

## Mask on the way in

`A09:2025` · ASVS 16.2.5 · `CWE-532`

Redaction at the sink is too late for three reasons: the value already exists in process
memory and crash dumps, it traverses every buffer and shipper before the sink, and the sink
is where a config change or a new destination silently disables the filter. A processor
inside the logger runs on every call by construction.

```python
# Vulnerable: the whole body reaches the log. Password included
logger.info("login attempt: %s", request.json)

# Fixed: a structlog processor drops and masks by key, before any renderer
import structlog

DENY = {"password", "passwd", "secret", "token", "authorization",
        "api_key", "private_key", "card_number", "cvv", "ssn", "national_id"}
PARTIAL = {"session_id", "refresh_token", "email"}

def scrub(logger, method_name, event_dict):
    for key in list(event_dict):
        low = key.lower()
        if any(d in low for d in DENY):
            event_dict[key] = "[REDACTED]"
        elif low in PARTIAL:
            event_dict[key] = _fingerprint(event_dict[key])
    return event_dict

def _fingerprint(value: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        scrub,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)
```

TypeScript, with pino's redaction plus an explicit allowlist on request bodies:

```typescript
import pino from "pino";

export const log = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: {
    paths: [
      "req.headers.authorization", "req.headers.cookie",
      "*.password", "*.token", "*.apiKey", "*.cardNumber", "*.ssn",
    ],
    censor: "[REDACTED]",
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: { level: (label) => ({ level: label }) },
});

// Never log req.body. Pick fields
log.info({ event: "authn_login_fail", actor: email, source_ip: req.ip });
```

Pino's `redact` uses fixed paths, so a nested or renamed field slips past. Do not log whole
objects and rely on it - treat it as the second layer, with named-field logging as the first.

Hashing a session ID keeps correlation (same hash means same session) without giving a log
reader a usable credential. Truncating to a prefix does not: `sess_a1b2...` plus a short
keyspace is often enough to guess.

Java, with a Logback converter so masking cannot be bypassed by a careless call site:

```java
public class MaskingConverter extends MessageConverter {
    private static final Pattern BEARER =
        Pattern.compile("(?i)\\b(bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}");
    private static final Pattern PAN =
        Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b");

    @Override
    public String convert(ILoggingEvent event) {
        String msg = super.convert(event);
        msg = BEARER.matcher(msg).replaceAll("$1 [REDACTED]");
        return PAN.matcher(msg).replaceAll("[REDACTED-PAN]");
    }
}
```

Honest limitation: a pattern-based converter is a net, not a guarantee. It catches known
shapes and misses a token in a field it does not recognise. It exists because someone will
eventually log a whole object; the primary control is still logging named fields.

## Never log

`CWE-532` · ASVS 16.2.5 · OWASP Logging Cheat Sheet

Not logged at all: passwords, API keys, private keys, encryption keys, access and refresh
tokens, database connection strings, full card numbers, CVV, government identifiers, health
data, application source code.

Hashed or partially masked only: session identifiers, email addresses where the jurisdiction
requires it, anything classified above what the log store is cleared to hold.

Never log the full request body on an authentication endpoint. That single habit accounts for
most plaintext passwords found in log stores.

If data is logged at a classification the log store is not approved for, the store inherits
the classification, and with it encryption, retention, and disclosure obligations. Logging
less is cheaper than protecting more.

## Log injection

`A09:2025` · ASVS 16.4.1 · `CWE-117`

The failure people never think about. User input containing a newline writes a second line
that looks like a real entry.

```python
# Vulnerable: username goes into a free-text line unescaped
logger.info("login failed for user %s", username)
```

A username of:

```text
attacker\n2026-07-28T10:00:00Z INFO authz_admin actor=1 action=role.grant target=attacker outcome=success
```

produces two lines. The second is indistinguishable from a genuine admin grant, and it
forges an action attributed to another actor. Investigators read it as fact. Worse, if the
sink is a terminal or a log viewer that renders escapes, ANSI sequences let the attacker
overwrite earlier lines on screen or hide their own with a colour that matches the background.

```python
# Fixed: structured JSON. The value cannot escape its field
log.warning("authn_login_fail", actor=username, source_ip=request.remote_addr)
```

JSON encoding turns `\n` into the two characters `\` and `n` inside a string value. There is
no newline in the output, so there is no second entry. The parser also refuses to treat a
field value as a record boundary.

Where free text is unavoidable - a legacy sink, a syslog line - strip control characters
explicitly:

```python
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

def sanitize(value: str, limit: int = 256) -> str:
    return _CONTROL.sub("\ufffd", str(value))[:limit]
```

The tempting wrong fix is replacing `\n` alone. That leaves `\r` (many viewers treat a bare
CR as a line break), `\x1b` (ANSI), `\x08` (backspace, which rewrites the visible line), and
`\x00` (truncates C-based parsers). Strip the whole control range, and cap the length or one
field can push a real entry out of a size-limited record.

Go, using `slog` so encoding is not a per-call-site decision:

```go
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

logger.Warn("authz_fail",
    slog.String("actor", actorID),
    slog.String("action", "invoice.read"),
    slog.String("target_id", invoiceID),
    slog.String("outcome", "denied"),
    slog.String("request_id", reqID),
)
```

## Structured logging

`A09:2025` · ASVS 16.2.4

Free text does not scale to alerting. `"user bob failed login from 1.2.3.4"` needs a regex
per message format, and the regex breaks the day someone rewords the string. A field named
`actor` does not.

- One event per line, JSON, newline-delimited
- Stable field names across services. `actor` everywhere, not `user_id` here and `uid` there
- Stable event names. Never put a variable into the event name
- Types stable per field. `target_id` is always a string, even when it holds a number
- Free text allowed in `description`, never load-bearing

Treat the schema as an API. A renamed field breaks every detection rule that reads it, and
the rule fails silently - it returns zero results rather than an error.

## Correlation IDs

`A09:2025` · ASVS 16.2.1, 16.2.4

Accept an inbound `traceparent` or `X-Request-ID`, generate one when absent, bind it to the
context so every log call includes it, and propagate it on every outbound call.

```typescript
import { randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";

const als = new AsyncLocalStorage<{ requestId: string }>();
const SAFE_ID = /^[A-Za-z0-9._-]{1,64}$/;

app.use((req, res, next) => {
  const inbound = req.header("x-request-id");
  const requestId = inbound && SAFE_ID.test(inbound) ? inbound : randomUUID();
  res.setHeader("x-request-id", requestId);
  als.run({ requestId }, next);
});

export const ctxLog = () => log.child({ request_id: als.getStore()?.requestId });
```

Validate the inbound header. It is user-controlled, so it is both a log injection vector and
a way to poison correlation by reusing another request's ID. Generating your own on a failed
validation is the right call.

Return the ID to the client in the response and in error bodies. That is what makes a generic
error message (ASVS 16.5.1) supportable: the user quotes the ID, you find the trace, and the
stack trace never left the server.

## Audit trail vs application log

`A09:2025` · ASVS 16.4.2, 16.4.3

Two systems, not one stream with two log levels.

| | Application log | Audit trail |
|---|---|---|
| Purpose | Debugging, ops | Non-repudiation, compliance, forensics |
| Retention | Days to weeks | Months to years, by regulation |
| Who reads it | Most engineers | Named roles, and reads are themselves logged |
| Mutability | Rotated and deleted freely | Append-only. No `UPDATE`, no `DELETE` |
| Loss tolerance | Some loss acceptable | Loss is a reportable event |
| Writes | Best effort | Committed with the transaction it describes |

Append-only is a permission grant, not a comment:

```sql
CREATE TABLE audit_log (
    id           BIGSERIAL PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    request_id   TEXT,
    source_ip    INET,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash    BYTEA,
    entry_hash   BYTEA NOT NULL
);

REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM app_user;
GRANT INSERT, SELECT ON audit_log TO app_user;
```

`TIMESTAMPTZ`, not `TIMESTAMP`. A naive timestamp is unusable the moment a second region or a
DST transition enters the picture, and you cannot recover the offset afterwards.

Hash chaining makes deletion detectable:

```python
def append_audit(conn, entry: dict) -> None:
    with conn.transaction():
        prev = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE"
        ).scalar()
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        entry_hash = hashlib.sha256((prev or b"") + payload).digest()
        conn.execute(
            "INSERT INTO audit_log (actor_id, action, target_type, target_id,"
            " outcome, request_id, source_ip, detail, prev_hash, entry_hash)"
            " VALUES (%(actor_id)s, %(action)s, %(target_type)s, %(target_id)s,"
            " %(outcome)s, %(request_id)s, %(source_ip)s, %(detail)s, %(prev)s, %(hash)s)",
            {**entry, "prev": prev, "hash": entry_hash},
        )
```

Removing an entry breaks every subsequent hash, so a verifier detects it. `FOR UPDATE`
serialises appends; without it, concurrent writers chain from the same predecessor and the
chain forks.

Be honest about the limit: hash chaining detects nothing against an attacker with write
access to the whole table, because they recompute the chain. Tamper evidence requires an
anchor outside the system - periodically publish the head hash to a separate account, a WORM
bucket with object lock, a signed transparency log, or a third party. Without external
anchoring, a hash chain is an integrity check against accidental loss and partial compromise,
not proof against a determined insider. Say that rather than claiming the log is immutable.

ASVS 16.4.3 wants logs shipped to a logically separate system, so a breach of the application
does not compromise them. Same host, same trust zone, same service account is the common
design failure.

## Alert, do not just collect

`A09:2025`

A09 was renamed in 2025 from Monitoring to Alerting. The point is that a dashboard nobody
opens is not a control.

For each security event, name the rule. For each rule, name the emitter and the test. See
[references/detection-rules.md](references/detection-rules.md) for the rules worth having:
impossible travel, privilege escalation, bulk export, repeated authorization denial, and the
deadman rule on log volume dropping to zero.

The deadman rule deserves its own mention. Every other detection silently stops working when
the pipeline breaks. It is the only rule that fires when logging itself fails.

Two conditions from A09 that are about alert quality rather than log presence: too many false
positives so real alerts are lost, and alerts nobody can action because the playbook is
missing. A codebase can pass every logging check and still be in this category.

Free self-test, also from A09: run ZAP or Burp against staging. If nothing fires, the answer
to "would we detect an attack" is no.

## SIEM integration

`A09:2025` · ASVS 16.2.4, 16.4.3

What a SIEM needs from your application, in priority order:

1. Parseable output. JSON on stdout, one object per line. No multi-line stack traces mixed
   into the same stream
2. A stable event name it can key a rule on
3. Normalised field names shared across services, so one rule covers all of them
4. Its own timestamp, in UTC, distinct from ingestion time. Ingestion lag is not event time
5. A correlation ID that survives service hops
6. Consistent severity, set by the event type rather than by the developer's mood
7. Enough context to triage without opening the code

Normalisation is the work. If three services call the same concept `user_id`, `uid`, and
`actorId`, either the application normalises at emission or the SIEM does it at ingest with a
mapping that nobody maintains. Normalise at emission - a shared logging module, not a
convention in a wiki.

Map to an existing schema (ECS, OCSF, CEF) if your SIEM prefers one. Any consistent schema
beats a bespoke one, because rule libraries exist for the standard ones.

## Failure modes

`A10:2025` · ASVS 16.5.2, 16.5.3

Three ways a logging subsystem takes down the thing it was protecting.

Blocking the request path. A synchronous write to a remote sink puts network latency inside
your p99, and an unreachable sink becomes an outage.

```python
# Vulnerable: an HTTP POST per log line, in-band
def audit(event):
    requests.post("https://siem.internal/ingest", json=event, timeout=30)

# Fixed: bounded queue, background flush, drop with a counter when full
import queue, threading

_q: queue.Queue = queue.Queue(maxsize=10_000)
_dropped = 0

def audit(event):
    global _dropped
    try:
        _q.put_nowait(event)
    except queue.Full:
        _dropped += 1          # exported as a metric, alerted on
```

Dropping with a visible counter is honest degradation. Silently blocking is not, and an
unbounded queue converts a slow sink into an out-of-memory kill.

One exception: an audit entry that must not be lost belongs in the same database transaction
as the change it describes, not in a queue. Accept the latency there - that is what makes the
trail trustworthy. Application logs go through the queue; audit entries commit with the write.

Unbounded growth as a DoS. Attacker-controlled input that generates a log line per request,
with no rate limit and no rotation, fills the disk. A full disk stops the database and the
application together. Cap log size, rotate, alert on filesystem usage, and rate-limit
repetitive events. Never let a user-controlled string set the log level or the message length.

Losing logs on crash. Buffered writes lost on `SIGKILL` are exactly the entries an attacker
wants gone. Flush security events synchronously to a local durable sink even when the remote
ship is async, and register a signal handler that drains the queue on shutdown. Also log
`sys_crash` from the last-resort handler (ASVS 16.5.4) - in Go, that is a `recover()` in
middleware, since the language has no exceptions.

## Log access control

`A09:2025` · ASVS 16.4.2 · `CWE-532`

Logs are a data store containing a projection of everything the application ever did. Treat
them like the database.

- Read access to the audit trail limited to named roles. Access to it is itself logged
- No blanket "engineering" group on the production log sink
- Log viewers respect tenancy. A support tool that searches all logs is a cross-tenant read
- Exports from the log platform are logged and rate-limited
- The application's own service account cannot delete what it wrote

A09 lists exposing logging and alerting events to users as a condition of the category, and
routes it back to A01 Broken Access Control. An admin log viewer without an authorization
check is an access control finding, not a logging one.

## Privacy and compliance

`A09:2025` · ASVS 16.2.5 · GDPR Art. 15, 17

The tension is real and does not resolve cleanly. GDPR Article 17 gives a data subject the
right to erasure. An audit trail is required to be append-only and is often retained for
years under a separate obligation. Both cannot be fully satisfied.

What works in practice:

- Pseudonymise at write time. Store an internal actor ID in the audit trail, never the name
  or email. Erasure then deletes the identity mapping in the user table, and the audit
  entries survive as `actor_id=8f3c...` with no route back to a person
- Rely on the legal-obligation and legitimate-interest bases for security logs, and document
  which one applies per stream - that is what makes a retention period defensible
- Set a retention period per stream and enforce it automatically. "We keep everything forever"
  is a finding under both GDPR and A09's own inventory requirement
- Keep the log inventory (ASVS 16.1.1) current enough to answer a subject access request
  without a codebase archaeology project
- Minimise at source. The field you never logged needs no erasure story

The honest position: pseudonymisation narrows the conflict, it does not remove it. A source IP
plus a timestamp is personal data in many readings, and it is also the field you most need for
detection. Decide with counsel per jurisdiction, write the decision down, and do not pretend
the standard settles it.

## Test the log

`A09:2025` · ASVS 16.3.3

An unasserted log line is deleted by the next refactor and nobody notices until an incident.

```python
def test_denial_emits_audit_event(client, caplog):
    resp = client.get("/api/invoices/999", headers=other_users_token)
    assert resp.status_code == 404

    events = [json.loads(r.message) for r in caplog.records]
    denial = next(e for e in events if e["event"] == "authz_fail")
    assert denial["actor"] == "user-2"
    assert denial["target_id"] == "999"
    assert denial["outcome"] == "denied"

def test_password_never_logged(client, caplog):
    client.post("/login", json={"email": "a@example.test", "password": "hunter2"})
    assert "hunter2" not in caplog.text

def test_newline_in_username_cannot_forge_entry(client, caplog):
    client.post("/login", json={"email": "x\nINFO forged", "password": "y"})
    for record in caplog.records:
        assert record.message.count("\n") == 0
```

The second and third tests are the ones to copy. They fail loudly the day someone adds
`logger.info(request.json)` or switches a handler to a free-text formatter.

## Sources

- <https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>
- <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html>
