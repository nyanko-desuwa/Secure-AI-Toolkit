# Common Compliance Mapping Mistakes

This skill helps engineers produce evidence and map implemented controls. It is not legal advice,
does not make an organisation compliant, and cannot certify anything. An auditor's interpretation
and the engagement scope govern.

## The control is documented but not enforced

This is the most dangerous compliance failure. The policy says every administrative action is
approved; the endpoint accepts the request without checking approval. An audit may pass because
the sample contains a signed procedure and selected tickets.

```typescript
// Vulnerable: approval is metadata; execution ignores it.
await deploy(change.commit);
await db.changes.update(change.id, { approvalId: req.body.approvalId });

// Fixed: execution requires a verified, bound, unused approval.
const approval = await approvals.consume({
  approvalId: validated.approvalId,
  commit: change.commit,
  environment: "production",
  actor: req.auth.subject,
});
if (!approval) throw new ForbiddenError("valid approval required");
await deploy(change.commit);
```

The fixed flow makes approval a precondition and binds it to the exact commit and environment.
The real risk was never the missing paperwork; it was that unauthorized code could deploy while
the audit still looked clean.

Mapping: `A01:2025`, `A08:2025`, ASVS V8/V15, ISO A.8.32 Change management, SOC 2 CC8.

## Mapping policy text as if it were operating evidence

A policy establishes expected behavior. It cannot show that encryption was enabled, reviews
occurred, logs were retained, or backups restored during the period.

Fix: keep the policy as design evidence, then generate operating artifacts from CI and runtime:
IaC policy result, deployed-resource export, review metadata, immutable logs, and restore results.

## Running the mapping backwards

Starting with ISO, PCI, or SOC 2 and filling a checklist encourages weak equivalence: "we need
logging, therefore our application log meets it." It may be mutable, incomplete, or outside the
reviewed system.

Fix: begin with the concrete control. Locate enforcement, tests, owner, and output. Then map its
actual behavior and scope to framework language.

## One artifact is claimed to prove compliance

A passing TLS scan can support cryptography and transmission-security requirements. It cannot
show key governance, access control, retention, incident handling, or effectiveness over time.

Fix: say "supports" or "provides evidence for," identify the period and assets covered, and list
residual evidence the requirement needs.

## Screenshots collected every quarter

Screenshots are easy to crop, stale immediately, and rarely bind state to a commit or resource.
They miss failures between collection dates.

Fix: export machine-readable state on every relevant change and on a schedule. Retain tool
version, policy version, resource identity, commit, timestamp, result, and artifact digest.
CI patterns belong in [`../../core/devsecops/`](../../core/devsecops/).

## A scanner ran but could not fail the build

```yaml
# Vulnerable: evidence exists, enforcement does not.
- run: scanner . || true
```

A report can satisfy a document request while vulnerable code still ships.

Fix: use an explicit blocking policy; require a separately approved, expiring exception with an
owner and compensating control. Map this to `A03:2025`, ASVS V15, ISO A.8.8, PCI Requirements 6
and 11, and SOC 2 CC7 only for the assets and scanner coverage actually tested.

## Audit logs are ordinary application logs

If the application's runtime identity can update or delete its logs, an attacker who compromises
the application can erase the evidence. Unstructured strings also lose actor, target, outcome,
and request linkage.

Fix: typed security events, a separate append-only sink, insert-only application credentials,
gap detection, access logging, retention, and tests. Map to `A09:2025`, ASVS V16, CWE-778,
ISO A.8.15/A.8.16, HIPAA 164.312(b), PCI Requirement 10, and SOC 2 CC7.

## Access review exports include everyone but review nothing

A user-role dump is inventory, not a review. It does not show who assessed each grant, what
"appropriate" meant, or whether removals completed.

Fix: export grant source, last use, owner, reviewer decision, decision reason, timestamp, removal
status, and exception expiry. Verify dormant and orphaned identities with negative checks.

## UI authorization is treated as a control

A hidden admin button cannot prevent a direct HTTP request. A screenshot of the hidden button is
not access-control evidence.

Fix: enforce authorization server-side, preferably in the data query; produce negative tests and
a deployed policy digest. Map to `A01:2025`, ASVS V8, ISO A.5.15/A.5.18/A.8.3, HIPAA
164.312(a)(1), PCI Requirements 7 and 8, and SOC 2 CC6.

## Encryption defaults are assumed

A cloud product may encrypt new resources by default, but scope, key ownership, old resources,
transport paths, and drift remain unknown.

Fix: declare encryption and TLS in IaC, policy-test it, query deployed state, and test certificate
validation. Map to `A04:2025`, ASVS V11/V12/V14, CWE-311/CWE-312, ISO A.8.24, GDPR Art 32,
PCI Requirements 3/4, and applicable HIPAA 164.312 safeguards.

## Rotation evidence exposes the secret

Including a value in a ticket or report creates a new copy that must be protected and rotated.
It proves possession, not rotation.

Fix: export only identifier, version, workload, created/expiry timestamps, rotation result, and a
failed-old-version test. Never publish values, hashes of low-entropy secrets, or recovery codes.

## Backup success is confused with recovery

A green backup job says bytes were written. It does not show decryptability, integrity, complete
dependencies, or recovery time.

Fix: restore in isolation on a schedule, verify integrity and application startup, measure the
recovery point and recovery time, then destroy the restored sensitive data safely. ISO A.8.13
and GDPR Art 32(1)(c)-(d) are relevant mappings.

## Requirement identifiers are recalled from memory

Framework editions renumber and titles change. A plausible but wrong ID damages audit work more
than an honest omission.

Fix: verify the ID and title from a fetched source, record source URL and check date, and pin the
edition. If access fails, use prose labelled unverified. This skill deliberately avoids granular
SOC 2 criterion IDs and PCI sub-requirement IDs because fetched sources did not expose them.

## Scope is omitted from the evidence

"Encryption enabled" is meaningless without account, region, resource type, environment, and
time. Evidence from staging does not establish production operation.

Fix: every artifact states population, exclusions, collection method, period, and freshness. Use
stable resource identifiers rather than display names.

## Exceptions never expire

A scanner exception or manual access grant without an expiry becomes the permanent control.

Fix: require owner, reason, affected assets, compensating control, creation time, hard expiry, and
re-approval. CI fails when an exception is malformed or expired.

## Synthetic samples quietly become real data

Copying a production identity export or audit row into a repository creates a privacy and access
problem inside the evidence system.

Fix: minimise exports, pseudonymise where identity is not necessary, restrict evidence storage,
and use unmistakably synthetic examples in source control.
