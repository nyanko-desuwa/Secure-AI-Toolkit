# Prompt Examples

Prompts that produce logging findings rather than a recital of log levels. Scope the code,
name the security event, and ask for both the emitter and the alert.

## Review what is missing

```text
Read src/api/ and list every path that returns 401, 403, or an ownership-hiding 404. For each,
show the authorization decision and whether it emits authz_fail with actor, action, target,
outcome, timestamp, source IP, request ID, and user agent. Report only missing or incomplete
events. Map each to A09:2025, ASVS 16.3.2, and CWE-778 or CWE-223.
```

Why it works: searching log calls finds the logging that exists. Starting from denial paths
finds the logging that is missing.

## Find sensitive values before they reach the sink

```text
Search this repo for log calls that receive a request, response, session, user, exception,
headers, cookies, or arbitrary object. Trace what fields the object can contain. Report every
path by which a password, token, session ID, key, full card number, government ID, health data,
or auth request body can reach the logger. Do not count sink redaction as the primary fix.
```

Why it works: it names the sources and the sink. A keyword search for `password` alone misses
a request object that contains one at runtime.

## Test log injection

```text
Review every place user-controlled data reaches a log call. Show whether the final renderer
escapes CR, LF, NUL, ANSI ESC, backspace, and record delimiters. For each unsafe path, provide
a working newline payload that forges an admin action and fix it with structured logging.
Map it to CWE-117 and ASVS 16.4.1.
```

Ask for the final renderer, not merely the call site. A JSON-looking string built with
concatenation is still free text.

## Design the event schema

```text
Design a stable JSON security-event schema for these services. It must support authentication
outcomes, authorization denials, privilege changes, admin actions, data exports, secret access,
and configuration changes. Include actor, action, target, outcome, ISO 8601 UTC timestamp,
source IP, request ID, and user agent. Show structlog and pino emitters using the same names.
Do not include any sensitive field.
```

## Review an audit trail

```text
Review the audit_log table, its database grants, writer code, retention policy, and shipper.
Can the application or an administrator update, delete, truncate, or rewrite history? Does each
row identify actor, action, target, outcome, and request ID? If it uses hash chaining, state
whether the head is anchored outside the trust domain. Do not call it tamper-evident without
that anchor.
```

Why it works: "is it append-only" is answered by grants, not by a table name or a comment.

## Wire rules to emitters

```text
For every rule under security/detections/, identify the exact event name and fields it queries.
Find the deployed code path that emits them and the test that proves emission. Then do the
reverse: for every security event emitted by the application, identify its rule. Report orphan
rules, orphan events, and schema mismatches. Treat a rule with no emitter as never firing.
```

## Review alerting, not just collection

```text
Review our A09:2025 coverage. Check for tuned rules and current playbooks for impossible
travel, privilege escalation, bulk export, repeated authorization denial, token reuse, and log
volume dropping to zero. For each rule give owner, notification route, response SLA, last test
date, and false-positive rate. Do not mark a dashboard as an alert.
```

## Test resilience

```text
Trace the application log and audit paths during: remote sink timeout, queue full, full disk,
missing file permissions, graceful shutdown, SIGKILL, and database rollback. State whether the
request blocks, the action fails closed, events drop visibly, or audit and business state can
diverge. Map findings to A09:2025 and ASVS 16.5.
```

## Review privacy and access

```text
Inventory every log field that is personal data. For each stream give purpose, legal basis,
readers, retention, deletion mechanism, and pseudonymisation. Then identify where GDPR access
or erasure rights conflict with append-only audit requirements. State the unresolved tension;
do not claim pseudonymisation makes the data anonymous.
```

## Write regression tests

```text
For this login and authorization middleware, add tests that assert: failures emit the expected
security event; every required field exists; a password and bearer token never appear in
captured output; newline and ANSI input cannot create a second record; and the event name still
matches the SIEM rule. Do not snapshot the entire line - assert the stable schema fields.
```

## Triage a leaked token

```text
A live access token appeared in this log. Identify every copy: local file, queue, shipper,
SIEM index, archive, backup, error tracker, and vendor destination. Give the order of response:
revoke, rotate, investigate. Then fix emission so the value never enters the pipeline. Deleting
one index is not remediation.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Add more logging" | Usually adds whole-object dumps and secrets. Name the event and fields |
| "Make our logs secure" | No scope: emission, data, injection, storage, access, and alerting are different reviews |
| "Redact passwords in Splunk" | Sink redaction is too late. The value already crossed buffers and shippers |
| "Use JSON logging" | JSON is only safe if a real encoder builds it; says nothing about what fields are included |
| "Make the audit log immutable" | No threat model. Hash chaining without external anchoring is not full tamper evidence |
| "Set up monitoring" | A09:2025 emphasises alerting. Ask who is notified and what they do |
| "Log all requests for forensics" | Captures credentials and PII. Ask for a field allowlist |
| "Keep logs forever" | Conflicts with minimisation and erasure. Set retention per stream |
| "Alert on every failure" | Produces a page storm and gets muted. Ask for grouping and thresholds |
| "Check our SIEM rule" | The rule can be correct and still have no emitter. Check end to end |
