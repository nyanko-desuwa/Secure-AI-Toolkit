---
name: compliance
description: 'Implement privacy and compliance controls in code - GDPR data subject rights, retention and deletion jobs, consent records, data inventory, audit evidence, PCI scope reduction, HIPAA safeguards. Triggers: "GDPR", "compliance", "data retention", "right to erasure", "consent", "PII", "PCI DSS", "HIPAA", "SOC 2", "ISO 27001", "audit evidence", "tuân thủ", "quyền xóa dữ liệu".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Compliance and Privacy Engineering

Compliance is not security. A control can pass an audit and still be exploitable: a
quarterly access review signed off in a spreadsheet says nothing about the service account
with a wildcard IAM policy that nobody reviewed. The reverse is also true and less often
admitted - a genuinely secure system with no evidence trail fails the audit, because the
auditor cannot test a control they cannot observe.

This skill covers the half of compliance that is code: deletion that actually deletes,
consent that records a decision, retention enforced by a job, and logs that can answer a
breach question inside 72 hours.

## When to Use

- Building or reviewing a data subject request path - access, erasure, portability, rectification
- Writing a deletion or retention job, or discovering there is none
- Storing consent, preferences, or an opt-out signal
- Adding a field that holds personal data, or a new analytics event
- Reviewing what reaches logs, telemetry, error trackers, or a data warehouse
- Preparing evidence for SOC 2, ISO/IEC 27001, PCI DSS, or HIPAA
- Deciding whether a payment or health flow can be kept out of scope entirely
- Answering "which systems hold this person's data" and finding nobody knows

## What This Skill Is Not

It is engineering guidance for implementing controls. Scope determination, lawful basis
assessment, breach notifiability decisions, and certification readiness need qualified
counsel and a real auditor. See [README.md](README.md#limitations) - that section is not
boilerplate, read it before quoting anything here to a regulator.

## Workflow

### 1. Find the data

You cannot delete, export, or protect data you cannot locate. Before any control, produce
the inventory: which tables, which columns, which log streams, which third parties, which
backups, which warehouse tables derived from them.

Tag at the schema level so the map is generated, not maintained by hand. See
[best-practices.md](best-practices.md#data-inventory-as-code). GDPR Art 30 (records of
processing) is the paperwork; the machine-readable map is what makes it true.

### 2. Name the basis and the purpose

Every field answers: why do we hold this, under what lawful basis (Art 6), for what purpose
(Art 5(1)(b)), and for how long (Art 5(1)(e)). A field with no answer is a finding - it is
either data minimisation (Art 5(1)(c)) failure or an undocumented purpose.

### 3. Implement the rights

Access (Art 15), rectification (Art 16), erasure (Art 17), portability (Art 20). Each is an
endpoint or a job, not a policy document. Erasure is the hard one: enumerate every copy -
replicas, backups, logs, caches, search indexes, warehouse, processors - and state for each
whether it is deleted, expires, or is crypto-shredded. See
[best-practices.md](best-practices.md#erasure-across-every-copy).

### 4. Enforce retention in a job

A retention policy in a wiki deletes nothing. TTL runs on a schedule, is monitored, and
fails loudly. See [best-practices.md](best-practices.md#retention-enforced-by-a-job).

### 5. Keep PII out of the exhaust

Logs, metrics, traces, analytics, crash reports, support tickets, LLM prompts. This is the
most common privacy finding in production systems and the hardest to unwind, because those
sinks are usually append-only and shipped to a third party. Masking mechanics live in
`core/logging-audit`; the consequence - a new processor, a new inventory entry, and a
deletion obligation you cannot honour - lives here.

### 6. Produce the evidence

For every control, name the artifact that proves it ran: the append-only audit record, the
job run history, the access review output, the alert that fired. A control with no artifact
is untestable and will be written up as a deficiency. See
[best-practices.md](best-practices.md#audit-evidence-that-survives-a-type-ii).

### 7. Verify

Run [checklist.md](checklist.md). Every unchecked box is a fix or a stated limitation.

## Severity

Rank by how many people are affected, how sensitive the data is, and whether the exposure is
reversible. Personal data leaves a system permanently; unlike a session token, it cannot be
rotated.

- **Critical** - special-category or payment data exposed or stored in cleartext; PII shipped
  to a third party with no contract; erasure demonstrably not performed on live systems
- **High** - PII in logs or analytics with no masking; no retention limit on a table of
  personal data; consent unrecorded so no lawful basis can be evidenced; no audit trail on a
  privileged path, so a breach question cannot be answered at all
- **Medium** - soft delete presented as erasure with replicas out of scope; consent stored
  without timestamp or version; access review performed but not evidenced
- **Low** - inventory incomplete for non-personal fields; retention documented but the job
  lacks alerting

Do not inflate. "GDPR violation" is a legal conclusion. Report the technical fact: the field
is unencrypted, the job does not exist, the log contains the email address.

## Related Skills

- `core/logging-audit` - masking mechanics, append-only trails, log injection, alerting
- `advanced/incident-response` - the process that meets the 72-hour clock
- `core/secrets-management` - key custody for crypto-shredding
- `core/database-security` - column encryption, row-level security, backup handling
- `core/cloud-security` - bucket retention policy, object lock, data residency
- `core/owasp-security` - the wider Top 10 and ASVS mapping
- `core/ai-security` - prompts and training data as a new PII sink

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the guidance cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - one file per standard, version-pinned with a check date
- [examples/](examples/) - seven vulnerable/fixed pairs
