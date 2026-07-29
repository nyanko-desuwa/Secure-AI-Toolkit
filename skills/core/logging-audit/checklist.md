# Logging and Audit Checklist

Run the sections that match the change. Mark every item pass, fail, or not applicable. A
not-applicable mark needs a reason. Do not mark a runtime item pass from source code alone.

## Inventory and schema (`A09:2025` · ASVS 16.1.1, 16.2.1–16.2.4)

- [ ] The logging inventory names every layer, stream, format, destination, reader, and retention period
- [ ] Every security entry has actor, action, target, outcome, timestamp, source IP, request ID, and user agent
- [ ] Timestamps are UTC or include an explicit timezone offset, and time sources are synchronized
- [ ] Event names and field names are stable across services; event names contain no variable IDs
- [ ] JSON is newline-delimited and machine-parseable; free text is not load-bearing
- [ ] `request_id` or `trace_id` is generated or safely accepted at the boundary and propagated across service calls
- [ ] The application writes only to documented destinations
- [ ] The SIEM parses the entry and can correlate it with events from another service

## Events (`A09:2025` · ASVS 16.3.1–16.3.4 · CWE-778, CWE-223)

- [ ] Authentication successes and failures are emitted, including factor or authentication method
- [ ] Every authorization denial is emitted with actor and target
- [ ] Sensitive-data access is emitted when the application targets ASVS Level 3 behaviour
- [ ] Privilege, role, and permission changes are emitted with old and new values
- [ ] Admin actions, data exports, secret access, and configuration changes are emitted
- [ ] Server-side input-validation, business-logic, anti-automation, and control-bypass attempts are emitted
- [ ] Unexpected errors and security-control failures are emitted without secrets or stack traces
- [ ] Each security event has a named detection rule, or the reason it is not alertable is documented
- [ ] Tests assert the security event beside the success or denial assertion

## Data protection (`A09:2025` · ASVS 16.2.5 · CWE-532)

- [ ] Passwords, tokens, session IDs, keys, full card numbers, CVV, government IDs, and health data never reach a logger
- [ ] Authentication endpoints never log the full request body
- [ ] Logs contain secret names, not secret values
- [ ] Session identifiers and other identifiers are hashed or partially masked only when correlation is required
- [ ] Masking runs before rendering, buffering, queueing, or shipping - not only at the sink
- [ ] Logging classification matches the data classification; encryption and access controls follow it
- [ ] Log exports and log-reader access are themselves logged and authorized
- [ ] PII minimisation, pseudonymisation, legal basis, and retention are documented per stream

## Log injection (`A09:2025` · ASVS 16.4.1 · CWE-117)

- [ ] Structured encoding prevents user input from creating a second record
- [ ] Legacy free-text sinks remove CR, LF, NUL, ANSI escape, backspace, and other control characters
- [ ] User-controlled values have a maximum length
- [ ] Tests send newline, carriage return, NUL, ANSI escape, and delimiter payloads
- [ ] A log viewer cannot render a user value as terminal control sequences

## Audit integrity (`A09:2025` · ASVS 16.4.2–16.4.3)

- [ ] The audit trail is separate from the application log, with its own retention, readers, and controls
- [ ] Audit storage is append-only to the application principal: no `UPDATE`, `DELETE`, or `TRUNCATE`
- [ ] Logs are transmitted to a logically separate system and survive application compromise
- [ ] An audit entry identifies actor, action, target, outcome, and request ID
- [ ] Hash chaining or equivalent detects deletion and reordering
- [ ] The team has documented where the integrity anchor lives outside the application
- [ ] Audit-table and object-store access logs alert on delete, update, and policy changes

## Alerting (`A09:2025`)

- [ ] A rule alerts on impossible travel with a tuned false-positive baseline
- [ ] A rule alerts on privilege escalation and self-elevation
- [ ] A rule alerts on bulk export using row count and actor baseline
- [ ] A rule alerts on repeated denials grouped by actor and distinct target
- [ ] A rule alerts when a log stream's volume drops to zero
- [ ] A rule alerts on token reuse and use after session expiry
- [ ] Each rule has an owner, severity, notification route, response SLA, and current playbook
- [ ] A staging DAST run (ZAP or Burp) produces the expected security alert
- [ ] Alert volume and false positives are reviewed; rules are not silently muted

## Runtime resilience (`A09:2025` · ASVS 16.5.1–16.5.4)

- [ ] A remote sink failure does not block the request path or grant access
- [ ] Queues are bounded; drops increment a metric and page when the threshold is exceeded
- [ ] Audit entries that must not be lost commit with the business transaction
- [ ] Rotation, retention, and disk-usage limits prevent unbounded log growth and disk DoS
- [ ] Crash and shutdown paths flush security events or record the loss
- [ ] A last-resort error boundary emits an event and returns a generic response
- [ ] Authorization and validation errors fail closed when logging or an external dependency fails
- [ ] Tests cover sink outage, full disk, missing permissions, queue full, and process crash

## Privacy and access (`A09:2025` · ASVS 16.1.1, 16.2.5, 16.4.2)

- [ ] Production log access is limited to named roles, not a broad engineering group
- [ ] Tenant boundaries apply in log search and export tools
- [ ] Retention is set per stream and enforced automatically
- [ ] The GDPR erasure/access position is documented for immutable audit data
- [ ] Pseudonymisation mapping can be erased without rewriting the audit trail
- [ ] The team states the unresolved tension instead of claiming both erasure and immutability are absolute

## Before returning

- [ ] Relevant tests and a build or compile step ran, with output reported honestly
- [ ] Deliberately skipped sections have a one-line reason
- [ ] Any unverifiable deployment claim is stated as unverifiable
- [ ] No labelled-vulnerable block was copied into production code
