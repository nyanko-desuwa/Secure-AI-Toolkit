---
name: logging-audit
description: 'Decide what to log, what never to log, and what to alert on. Covers security event taxonomy, masking, log injection, audit trails, SIEM integration, and detection rules. Triggers: "logging", "audit log", "log injection", "SIEM", "alerting", "detection rule", "ghi log", "nhật ký kiểm toán".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Logging and Audit

Logging is a security control and a security risk at the same time. A log that misses the
authorization denial cannot detect the attack. A log that captured the bearer token became
the attack surface. Both failures live in `A09:2025 Security Logging and Alerting Failures`.

The 2025 rename matters: alerting, not monitoring. A log nobody is alerted on is storage.

## When to Use

- Adding or reviewing logging in auth, authorization, admin, export, or payment paths
- Designing an audit trail, or discovering the "audit trail" is the application log
- Writing a detection rule, or asking why an existing rule has never fired
- Responding to a secret found in a log line
- Reviewing a log pipeline: format, sink, retention, access control
- Anything that touches PII and a log at the same time

## Two Failure Directions

| Direction | Looks like | Standard |
|---|---|---|
| Too little | 403 with no event, only successful logins recorded, no alert on bulk export | CWE-778, ASVS 16.3 |
| Too much | Passwords, tokens, session IDs, full request bodies in the log | CWE-532, ASVS 16.2.5 |
| Wrong shape | Free-text lines an attacker can forge entries into | CWE-117, ASVS 16.4.1 |

Most codebases manage all three simultaneously. Check for each; do not assume that a
verbose log is a complete one.

## Workflow

### 1. Inventory

ASVS 16.1.1 asks for a documented inventory: what each layer logs, in what format, where it
is stored, who can read it, and for how long. If none exists, the first finding is that
nobody can answer "would we have seen this".

Four questions per log stream:

- What events does it carry, and which of those are security events?
- What sensitive fields can reach it?
- Where does it go, and can the application delete it there?
- What alerts on it?

### 2. Name the event

Use a stable event name, not a sentence. `authz_fail` is greppable, alertable, and survives
a copy-edit; `"User not allowed to do that"` does not. The OWASP Application Logging
Vocabulary gives a ready-made taxonomy — see
[references/detection-rules.md](references/detection-rules.md#event-vocabulary).

### 3. Emit it safely

Every entry carries actor, action, target, outcome, timestamp with timezone, source IP,
request ID, and user agent. Sensitive values are masked at construction, not at the sink.
See [best-practices.md](best-practices.md#required-fields) and
[best-practices.md](best-practices.md#mask-on-the-way-in).

### 4. Separate the audit trail

The audit trail and the application log are different systems with different retention,
different access control, and different tamper requirements. Do not put an append-only
requirement on a table your application can `UPDATE`. See
[best-practices.md](best-practices.md#audit-trail-vs-application-log).

### 5. Close the loop with an alert

For each security event, name the rule that fires on it. For each rule, name the code path
that emits the event. A rule with no emitter and an event with no rule are the same bug seen
from opposite ends. See [references/detection-rules.md](references/detection-rules.md).

Include the deadman rule: alert when log volume for a stream drops to zero.

### 6. Verify

Run [checklist.md](checklist.md). Every unchecked box is a fix or a stated limitation.

## Severity

Rank by what an attacker could do unobserved, and by what the log itself exposes.

- **Critical** — a live credential, session token, or bulk PII written to a log that ships to
  a third party or is readable by everyone in the organisation
- **High** — no log at all on authentication or authorization outcomes in a
  privileged path, so an active account takeover produces no evidence; or log injection that
  lets a user forge audit entries attributed to another actor
- **Medium** — events emitted but nothing alerts on them; audit trail the application can
  modify; timestamps without a timezone across services
- **Low** — inconsistent event naming, missing user agent, free-text message where a field
  would be better, with no exploitation path

"No logging" is not automatically critical. Missing logs on a public marketing page is low.
Missing logs on the admin role-grant endpoint is high. Say which and why.

## Related Skills

- `owasp-security` — the wider Top 10 and ASVS mapping
- `secrets-management` — what to do the hour after a token is found in a log
- `incident-response` — the process the logs exist to serve
- `secure-code-review` — finding the missing log during review
- `devsecops` — pipeline configuration, log shipping, alert delivery
- `api-security` — per-endpoint event coverage
- `cloud-security` — log sink IAM, retention policy, WORM storage

## Supporting Files

- [README.md](README.md) — purpose, configuration, limitations
- [checklist.md](checklist.md) — pre-return verification
- [best-practices.md](best-practices.md) — patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/](references/) — ASVS V16 requirements, A09 summary, detection rules
- [examples/](examples/) — eight vulnerable/fixed pairs
