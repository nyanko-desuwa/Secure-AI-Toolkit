# Compliance Verification Checklist

Run before returning code that touches personal data, payment data, health data, or an audit
trail. Mark each item pass, fail, or not applicable. "Not applicable" needs a one-line reason.

This checklist maps technical controls to framework intent. It is not an audit, and it is not
legal advice. Passing every item does not make an organisation certifiable, compliant, or
in-scope-free. See [README.md](README.md#limitations).

Only run the sections the change touches. A CSS fix needs none of them.

## Data Inventory

- [ ] Every new column, event, or payload field holding personal data is tagged in the schema
      or model, not in a wiki page
- [ ] The tag carries category, purpose, lawful basis, and retention period
- [ ] The inventory is generated from the tags, so it cannot drift from the code
- [ ] Special-category data (health, biometric, race, religion, sexual orientation, union
      membership) is tagged as such, not as generic PII
- [ ] Derived copies are listed: read replicas, warehouse tables, search indexes, caches,
      export files, analytics events
- [ ] Every third party that receives the field is named, with the field list it receives

## Data Minimisation and Purpose

GDPR Art 5(1)(b) purpose limitation, 5(1)(c) data minimisation.

- [ ] Each new field has a stated purpose that a reader can check against the code
- [ ] No field is collected "in case we need it later"
- [ ] Free-text fields that will inevitably hold personal data are either avoided or tagged
- [ ] Full date of birth is not stored where an age band or an over-18 boolean would do
- [ ] Identifiers sent to analytics are pseudonymous and cannot be joined back without a
      key you control

## Data Subject Rights

- [ ] Access (Art 15) returns the actual stored data, including data derived about the person,
      not a hand-written summary
- [ ] The access response is scoped to the requesting subject and re-authenticates them
- [ ] Rectification (Art 16) propagates to downstream copies, or the staleness is bounded
- [ ] Erasure (Art 17) enumerates every copy and states, per copy, deleted / expires /
      crypto-shredded / retained under an exemption
- [ ] Portability (Art 20) emits a structured, machine-readable format, not a PDF
- [ ] Each request produces an audit record: who asked, when, what was returned, who approved
- [ ] Requests are rate limited and logged, because the access endpoint is now the highest
      value target in the system

## Retention and Deletion

GDPR Art 5(1)(e) storage limitation.

- [ ] Every table of personal data has a retention bound expressed in code
- [ ] A scheduled job enforces it, with a run record and an alert on failure or on zero rows
      deleted when rows were expected
- [ ] The job is bounded (batch size, time budget) so it cannot lock the table
- [ ] Deletion is verified by a query, not by the job's exit code
- [ ] Log, metric, and trace retention is configured, not left at the vendor default
- [ ] Backup lifecycle is stated: how long backups live, and therefore how long a deleted
      record can still be restored
- [ ] Where deletion is impossible (immutable backups, object lock, ledger), crypto-shredding
      or a documented exemption is in place instead of a false claim

## Consent and Preferences

GDPR Art 6 lawful basis, Art 7 conditions for consent.

- [ ] Consent is stored as an event with subject, purpose, decision, timestamp, version of the
      text shown, and how it was captured
- [ ] Withdrawal is as easy as granting, and is recorded as its own event
- [ ] The current state is derived from the event history, never overwritten in place
- [ ] Processing checks the consent record at use time, not at signup time
- [ ] No pre-ticked boxes, no bundled consent, no consent inferred from silence
- [ ] An opt-out preference signal from the browser is honoured server-side, not just in the
      cookie banner

## PII in the Exhaust

`A09:2025` · ASVS V16 · CWE-532.

- [ ] No personal data in application logs, request logs, or error messages
- [ ] Masking happens before the log call, not in a downstream pipeline
- [ ] Crash and error reporters do not attach request bodies, headers, or environment
- [ ] Analytics events reviewed field by field
- [ ] Prompts and completions sent to a model provider are treated as a disclosure, with the
      same inventory and retention questions as any other processor
- [ ] URLs do not carry personal data in query strings, which land in proxy and CDN logs

Masking mechanics live in `core/logging-audit`. This checklist only asks whether they ran.

## Encryption

`A04:2025` · ASVS V11, V14 · CWE-311, CWE-312.

- [ ] Personal and payment data encrypted in transit with TLS, verification on
- [ ] Encryption at rest configured explicitly, with the setting visible in code or IaC
- [ ] The evidence artifact exists: the IaC resource, the cloud config query, or the
      TLS scan output
- [ ] Key custody stated: who can decrypt, who can destroy the key, and where that is logged
- [ ] Crypto-shredding, if relied on for erasure, uses a per-subject key that is genuinely
      destroyable

Key management belongs to `core/secrets-management`. Reference it, do not restate it.

## Audit Evidence

`A09:2025` · ASVS V16.

- [ ] Security-relevant events are written to an append-only or hash-chained store, separate
      from application logs
- [ ] Records carry actor, action, target, outcome, timestamp, and request ID
- [ ] The application's runtime role can insert but not update or delete
- [ ] Retention on the audit store covers the full observation period plus margin
- [ ] Gaps are detectable: sequence numbers, chain verification, or a heartbeat record
- [ ] Access to the audit store is itself logged

## Change Management

`A02:2025` · `A08:2025`.

- [ ] Branch protection requires review, and the setting is in a config file, not a memory
      of a UI toggle
- [ ] Commits or tags are signed, and CI verifies the signature
- [ ] Deploys record what was deployed, from which commit, by whom
- [ ] The CI gate fails the build rather than warning

CI gate patterns and SBOM-as-evidence live in `core/devsecops`.

## Before Returning

- [ ] Every claim about production state is labelled as verified or unverified
- [ ] No framework control ID, clause, or article number cited unless it was checked against
      the source in [references/](references/)
- [ ] Sample data in tests and fixtures is obviously synthetic
- [ ] Any control that cannot produce an artifact is reported as a gap, not silently passed
- [ ] Legal questions handed back as legal questions
