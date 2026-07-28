# Compliance Mapping Troubleshooting

This is engineering guidance, not legal advice or certification. When framework scope or
interpretation is disputed, record the technical facts and ask qualified counsel or the auditor.

## The requirement ID cannot be verified

Do not guess. Use this fallback:

1. State the control behavior and scope.
2. Describe the apparent framework intent in prose.
3. Label the mapping `unverified — source unavailable`.
4. Link the attempted source and date.
5. Ask the control owner or auditor to validate before the ID enters an audit package.

A missing ID is recoverable. A confident wrong ID may contaminate policies, tests, and reports.

## Two sources give different titles

Prefer the publisher's normative standard. Secondary summaries are discovery aids. Record both
URLs, edition, publication status, and access date. Do not silently combine wording.

For ISO/IEC 27001:2022, this skill uses verified control titles from a fetched secondary catalogue
because ISO's catalogue was inaccessible. Re-check against a licensed copy before external use.

## The auditor asks for framework-to-checklist mapping

Keep the implementation record technical-control first. Generate a reverse index as a view:

```text
canonical record: control -> evidence -> framework mappings
report view:      framework requirement -> linked canonical controls
```

Do not maintain both directions manually. They will drift and disagree.

## The control exists but produces no artifact

Add evidence generation to the control path or CI. Good artifacts are deterministic,
machine-readable, timestamped, scoped, and bound to a source commit or runtime resource.

If instrumentation would expose sensitive data, emit metadata and test outcomes rather than raw
values. If no safe artifact is possible, record the control as untestable and do not pass it.

## Evidence is only available from a console

Prefer an API or provider CLI export. If the provider offers no machine interface, record the
manual collection procedure, collector identity, timestamp, scope, and checksum. Treat a
screenshot as weak corroboration, not the primary artifact, and open a gap to automate it.

## Runtime state differs from IaC

Do not choose the convenient version. The mismatch is a control failure.

- Preserve the IaC policy result and runtime export.
- Identify whether drift was authorized.
- Block further deployment if the mismatch weakens a security property.
- Restore declared state or update the reviewed declaration through change management.
- Retain the reconciliation event as evidence.

## The scanner database changed after the build

A result is reproducible only with scanner version, rules/policy version, vulnerability database
timestamp or digest, input hash, and command configuration. Re-run when intelligence changes and
link the new result; never overwrite the historical artifact.

## CI cannot access production evidence safely

Use a dedicated read-only evidence identity with workload federation, short-lived credentials,
fixed queries, output minimisation, and access logging. It must not receive write privileges or
secret values. Split collection by account or tenant if a global reader creates excessive blast
radius.

## Access review data is too sensitive for CI artifacts

Store the full export in a restricted evidence repository. Put only a manifest in general CI:
population count, review period, exception count, completion status, artifact URI, and digest.
Pseudonymise subjects when reviewer identity is not required.

## The evidence contains secrets or personal data

Stop publication. Revoke exposed artifact links, rotate affected credentials, assess repository
history and downstream copies, and regenerate a minimised artifact. Evidence has its own access,
retention, deletion, and incident requirements.

## A control spans several services

Define the control boundary and population. Collect per-service artifacts into one signed
manifest. A partial collection must fail or declare the missing services; absence cannot look like
success.

## One service uses a compensating control

Document the original control objective, why the normal control cannot apply, the alternative,
its tests, owner, residual risk, and expiry/review point. Whether it is acceptable is a framework
and auditor decision, not an engineering assertion.

## A required control would break availability

Do not weaken it silently. Document the conflict, threat, affected requirement, failure mode,
and alternatives. Use staged rollout, emergency access with separate logging, or bounded failure
behavior. Security decisions fail closed unless an explicitly approved safety design says
otherwise.

## Backup restoration uses production data

Restore only into an isolated, access-controlled environment with equivalent encryption and
logging. Prefer synthetic restore tests where they can verify the mechanism. If real data is
necessary, minimise access, disable outbound integrations, record the legal/operational basis,
and destroy the restored copy on completion.

## Restore tests pass but recovery objectives fail

A technically successful restore can still miss the required recovery time or point. Preserve
measured values, report the objective miss, and map only the capability actually demonstrated.
Do not edit the expected value after the test.

## A secret rotates but old credentials remain valid

Rotation without revocation is additive credential creation. Test the new credential, switch
consumers, revoke the previous version after a bounded overlap, and prove the old version fails.
If a dependent system cannot refresh, record it as a control gap.

## Logs are immutable but incomplete

Immutability cannot recover events never written. Add schema enforcement, event coverage tests,
heartbeats or sequence checks, pipeline failure alerts, and a dead-letter path. Test dropped and
malformed events, not only valid writes.

## The control owner says the policy is enough

Demonstrate the enforcement path and an abuse case. If code allows the prohibited action, report
the technical finding even if the audit sample passed. Documentation without enforcement is the
risk, not a substitute for remediation.

## Legal retention conflicts with erasure

Do not resolve legal duties in code review. Identify every copy, freeze only the fields and period
supported by approved policy, restrict use, retain the decision and authority, and delete when the
hold expires. Counsel determines whether an exemption applies.

## Framework mappings disagree

They often test different properties. Separate:

- design: is the control suitably designed?
- implementation: is it deployed to the scoped population?
- operation: did it run throughout the period?
- effectiveness: did it produce the intended outcome?

Map each artifact only to the property it establishes. Ask the auditor which evidence is needed
for the engagement's period and sampling approach.

## The source edition changed

Freeze existing reports to their cited edition. Open a mapping migration: compare titles and
intent, mark changed IDs, update tests only after review, and preserve historical mappings. Do not
silently relabel old evidence under the new edition.

## Where implementation detail belongs

- CI gates, SBOM, provenance, SAST/SCA and IaC scanning:
  [`../../core/devsecops/`](../../core/devsecops/)
- Audit event design, masking and alerting: `../../core/logging-audit/`
- Key custody and secret rotation: `../../core/secrets-management/`
- Storage and backup protections: `../../core/database-security/`

Use this skill for the mapping and evidence contract. Use the related skill for implementation.
