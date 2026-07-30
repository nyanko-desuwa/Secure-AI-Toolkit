# Compliance Verification Checklist

Run before returning code that touches personal data, payment data, health data, or an audit
trail. Mark each item pass, fail, or not applicable. "Not applicable" needs a one-line reason.

This checklist maps technical controls to framework intent. It is not an audit, and it is not
legal advice. Passing every item does not make an organisation certifiable, compliant, or
in-scope-free. See [README.md](README.md#limitations).

Only run the sections the change touches. A CSS fix needs none of them.

## Data Inventory

- [ ] [recommended] Every new column, event, or payload field holding personal data is tagged in the schema
      or model, not in a wiki page
- [ ] [recommended] The tag carries category, purpose, lawful basis, and retention period
- [ ] [recommended] The inventory is generated from the tags, so it cannot drift from the code
- [ ] [recommended] Special-category data (health, biometric, race, religion, sexual orientation, union
      membership) is tagged as such, not as generic PII
- [ ] [recommended] Derived copies are listed: read replicas, warehouse tables, search indexes, caches,
      export files, analytics events
- [ ] [recommended] Every third party that receives the field is named, with the field list it receives

## Data Minimisation and Purpose

GDPR Art 5(1)(b) purpose limitation, 5(1)(c) data minimisation.

- [ ] [recommended] Each new field has a stated purpose that a reader can check against the code
- [ ] [recommended] No field is collected "in case we need it later"
- [ ] [recommended] Free-text fields that will inevitably hold personal data are either avoided or tagged
- [ ] [recommended] Full date of birth is not stored where an age band or an over-18 boolean would do
- [ ] [recommended] Identifiers sent to analytics are pseudonymous and cannot be joined back without a
      key you control

## Data Subject Rights

- [ ] [recommended] Access (Art 15) returns the actual stored data, including data derived about the person,
      not a hand-written summary
- [ ] [critical] The access response is scoped to the requesting subject and re-authenticates them
- [ ] [recommended] Rectification (Art 16) propagates to downstream copies, or the staleness is bounded
- [ ] [recommended] Erasure (Art 17) enumerates every copy and states, per copy, deleted / expires /
      crypto-shredded / retained under an exemption
- [ ] [recommended] Portability (Art 20) emits a structured, machine-readable format, not a PDF
- [ ] [recommended] Each request produces an audit record: who asked, when, what was returned, who approved
- [ ] [recommended] Requests are rate limited and logged, because the access endpoint is now the highest
      value target in the system

## Retention and Deletion

GDPR Art 5(1)(e) storage limitation.

- [ ] [recommended] Every table of personal data has a retention bound expressed in code
- [ ] [recommended] A scheduled job enforces it, with a run record and an alert on failure or on zero rows
      deleted when rows were expected
- [ ] [recommended] The job is bounded (batch size, time budget) so it cannot lock the table
- [ ] [recommended] Deletion is verified by a query, not by the job's exit code
- [ ] [recommended] Log, metric, and trace retention is configured, not left at the vendor default
- [ ] [recommended] Backup lifecycle is stated: how long backups live, and therefore how long a deleted
      record can still be restored
- [ ] [recommended] Where deletion is impossible (immutable backups, object lock, ledger), crypto-shredding
      or a documented exemption is in place instead of a false claim

## Consent and Preferences

GDPR Art 6 lawful basis, Art 7 conditions for consent.

- [ ] [recommended] Consent is stored as an event with subject, purpose, decision, timestamp, version of the
      text shown, and how it was captured
- [ ] [recommended] Withdrawal is as easy as granting, and is recorded as its own event
- [ ] [recommended] The current state is derived from the event history, never overwritten in place
- [ ] [recommended] Processing checks the consent record at use time, not at signup time
- [ ] [recommended] No pre-ticked boxes, no bundled consent, no consent inferred from silence
- [ ] [recommended] An opt-out preference signal from the browser is honoured server-side, not just in the
      cookie banner

## PII in the Exhaust

`A09:2025` · ASVS V16 · CWE-532.

- [ ] [critical] No personal data in application logs, request logs, or error messages
- [ ] [recommended] Masking happens before the log call, not in a downstream pipeline
- [ ] [recommended] Crash and error reporters do not attach request bodies, headers, or environment
- [ ] [recommended] Analytics events reviewed field by field
- [ ] [recommended] Prompts and completions sent to a model provider are treated as a disclosure, with the
      same inventory and retention questions as any other processor
- [ ] [recommended] URLs do not carry personal data in query strings, which land in proxy and CDN logs

Masking mechanics live in `core/logging-audit`. This checklist only asks whether they ran.

## Encryption

`A04:2025` · ASVS V11, V14 · CWE-311, CWE-312.

- [ ] [critical] Personal and payment data encrypted in transit with TLS, verification on
- [ ] [critical] Encryption at rest configured explicitly, with the setting visible in code or IaC
- [ ] [recommended] The evidence artifact exists: the IaC resource, the cloud config query, or the
      TLS scan output
- [ ] [recommended] Key custody stated: who can decrypt, who can destroy the key, and where that is logged
- [ ] [recommended] Crypto-shredding, if relied on for erasure, uses a per-subject key that is genuinely
      destroyable

Key management belongs to `core/secrets-management`. Reference it, do not restate it.

## Audit Evidence

`A09:2025` · ASVS V16.

- [ ] [critical] Security-relevant events are written to an append-only or hash-chained store, separate
      from application logs
- [ ] [recommended] Records carry actor, action, target, outcome, timestamp, and request ID
- [ ] [critical] The application's runtime role can insert but not update or delete
- [ ] [recommended] Retention on the audit store covers the full observation period plus margin
- [ ] [recommended] Gaps are detectable: sequence numbers, chain verification, or a heartbeat record
- [ ] [recommended] Access to the audit store is itself logged

## Change Management

`A02:2025` · `A08:2025`.

- [ ] [recommended] Branch protection requires review, and the setting is in a config file, not a memory
      of a UI toggle
- [ ] [critical] Commits or tags are signed, and CI verifies the signature
- [ ] [recommended] Deploys record what was deployed, from which commit, by whom
- [ ] [recommended] The CI gate fails the build rather than warning

CI gate patterns and SBOM-as-evidence live in `core/devsecops`.

## Before Returning

- [ ] [critical] Every claim about production state is labelled as verified or unverified
- [ ] [recommended] No framework control ID, clause, or article number cited unless it was checked against
      the source in [references/](references/)
- [ ] [recommended] Sample data in tests and fixtures is obviously synthetic
- [ ] [recommended] Any control that cannot produce an artifact is reported as a gap, not silently passed
- [ ] [recommended] Legal questions handed back as legal questions
