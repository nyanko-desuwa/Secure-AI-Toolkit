# Common Mistakes

Failures seen in generated and hand-written logging code. Each entry says what goes wrong,
why it goes wrong, the fix, and why the fix works.

## Logging only successful authentication

`A09:2025` · ASVS 16.3.1 · `CWE-778`

```python
# Vulnerable: the attack is the event that is missing
if verify_password(password):
    logger.info("login success", extra={"actor": user.id})
```

A credential-stuffing run leaves no application evidence. The only useful entry - the failed
attempt - was omitted.

Fix: emit both `authn_login_success` and `authn_login_fail`, with actor or attempted identity,
source IP, request ID, and authentication method. The fix closes the gap because the SIEM can
now count attempts by IP and actor, instead of inferring them from successful sessions.

## Logging a denial but returning the data

`A01:2025` · ASVS 16.3.2 · `CWE-223`

```python
# Vulnerable: logging is not enforcement
invoice = db.get(Invoice, invoice_id)
if invoice.owner_id != actor.id:
    logger.warning("authz_fail", extra={"actor": actor.id})
return invoice
```

The audit entry is true - a denial happened - but the response is still a data leak. It also
omits the target, so investigators cannot tell what was exposed.

Fix: scope the query by actor and emit the denial before returning 404. The query makes the
unauthorised object unavailable to the handler; the target field makes the event actionable.

## Logging an entire request object

`A09:2025` · ASVS 16.2.5 · `CWE-532`

```typescript
// Vulnerable: password, token, and payment fields go wherever req goes
logger.info({ event: "request", req });
```

A serializer added later can expose cookies, an authorization header, or a password reset
body. The log is replicated to agents, queues, backups, and vendors.

Fix: log named fields, and redact at the logger boundary before rendering. The fix closes the
common call-site mistake and keeps secrets out of every downstream copy. A sink regex is only
defence in depth: it runs after the secret has already crossed the process boundary.

## Masking only at the sink

`A09:2025` · ASVS 16.2.5 · `CWE-532`

```python
# Vulnerable: this value is plaintext in the in-process queue and any failed shipper
logger.info("token=%s", access_token)
# A downstream pipeline later replaces token=... with token=[REDACTED]
```

A crash dump, local file, retry queue, or second sink still has the value. A configuration
change can also bypass the sink filter.

Fix: do not pass the value to the logger at all. If correlation is needed, hash it before
emission with a keyed or appropriately scoped fingerprint. Masking on the way in means no
later component has to remember the rule.

## Free-text log injection

`A05:2025` · ASVS 16.4.1 · `CWE-117`

```java
// Vulnerable: CR/LF in username makes a forged record
log.warn("login failed username=" + username);
```

An attacker supplies `victim\nINFO authz_admin actor=1 action=role.grant outcome=success`.
A line-oriented viewer accepts the forged admin action. ANSI escape bytes can hide or rewrite
what a terminal displays.

Fix: emit a structured JSON event through the logging framework; for a legacy line sink,
remove all control characters, not just `\n`, and cap the value length. JSON encoding keeps
the newline inside one quoted field, so it cannot become a record boundary. Replacing only LF
is wrong because CR, ESC, backspace, and NUL have separate effects.

## Free text where fields are needed

`A09:2025` · ASVS 16.2.4 · `CWE-223`

```text
# Vulnerable
"User bob failed to read invoice 4192 from 10.0.0.4"
```

A rule needs a different regex for every rewording and cannot reliably distinguish an ID from
prose. It breaks when a user agent contains punctuation.

Fix: `{"event":"authz_fail","actor":"bob","target_id":"4192","source_ip":"10.0.0.4","outcome":"denied"}`.
The stable schema lets the SIEM group by actor and target without parsing a sentence.

## Audit row has actor but not target

`A09:2025` · ASVS 16.2.1 · `CWE-223`

```sql
-- Vulnerable: "admin did something" cannot reconstruct the transaction
INSERT INTO audit_log (actor_id, action, occurred_at)
VALUES (:actor, :action, now());
```

After an incident, nobody can tell which customer, role, file, or record was touched.

Fix: require `target_type`, `target_id`, and `outcome` as non-null columns. The fix closes the
investigation gap rather than making the row look more detailed: every high-value action now
has an object to scope and query.

## Privileged user can edit the audit trail

`A09:2025` · ASVS 16.4.2–16.4.3 · `CWE-778`

```sql
-- Vulnerable: the app role owns its own evidence
GRANT ALL ON audit_log TO app_user;
```

A compromised admin service can delete the role-grant history, then report a clean table.

Fix: revoke `UPDATE`, `DELETE`, and `TRUNCATE`; grant only `INSERT` to the application, ship
to a separate system, and alert on storage-layer changes. Hash chaining alone is not enough:
a writer who can rewrite the whole table can recompute the chain. External anchoring is needed
for tamper evidence against that writer.

## A rule exists but no event is emitted

`A09:2025` · ASVS 16.3.3 · `CWE-778`

```text
# SIEM rule, never produced by the service
alert when event == privilege_permissions_changed and to_role == "admin"
```

The SOC believes role grants are covered. The role-change handler only writes an ordinary
application message, so this alert has never fired.

Fix: name the emitter in the rule inventory and add a test that grants a role, asserts the
change, and asserts `privilege_permissions_changed`. The test turns a missing detection into a
build failure instead of a post-incident surprise.

## Timestamp without a timezone

`A09:2025` · ASVS 16.2.2 · `CWE-223`

```java
// Vulnerable: "2026-07-28 10:00" means different moments in different services
log.info("event={} at={}", event, LocalDateTime.now());
```

Impossible-travel and cross-service timelines become guesswork around regions and daylight
saving transitions. You cannot reconstruct the offset from the string later.

Fix: use `Instant.now()` and render ISO 8601 UTC, or include the explicit offset with
`OffsetDateTime`. The fix preserves the moment, not merely the wall-clock display.

## Blocking the request on a remote sink

`A09:2025` · ASVS 16.5.2 · `CWE-778`

```python
# Vulnerable: SIEM outage becomes an application outage
requests.post(SIEM_URL, json=event, timeout=30)
```

A dead sink holds every request for 30 seconds. Developers then disable logging to restore
availability, losing the evidence and the alert.

Fix: use a bounded asynchronous queue for application logs, export a dropped-event metric,
and alert on it. Keep must-not-lose audit writes in the business transaction instead. The
separation preserves availability without silently claiming the audit trail is complete.

## Unbounded log growth

`A06:2025` · ASVS 16.5.2 · `CWE-400`

```python
# Vulnerable: attacker controls both request rate and message size
while True:
    logger.warning("invalid input %s", request.body)
```

A burst fills the disk, which can stop the database and the application.

Fix: cap field and entry length, rate-limit repetitive events, rotate with a hard storage
budget, and alert on disk use and dropped events. Do not simply turn off security logging
when the disk is full; fail closed for the protected operation and surface the failure.

## One stream for app logs and audit logs

`A09:2025` · ASVS 16.1.1, 16.4.2

The ops team rotates the file every seven days, while compliance expects seven years. Giving
application developers read access also gives them the full audit history.

Fix: document separate streams, retention, readers, and tamper controls. The distinction
works because operational volume and forensic evidence have different security properties;
calling one a different log level does not create those properties.

## Sources

- <https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>
- <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
