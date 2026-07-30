# Compliance Mapping Prompts

These prompts run technical-control to framework. They do not request legal conclusions,
certification, or checklist theatre.

## Map one implemented control

```text
Read the implementation, tests, IaC, and runtime collection path for <control>. Start from what
the control actually enforces. Return:
1. implementation locations;
2. abuse case and negative test;
3. machine-readable evidence artifact and collection frequency;
4. systems, data, environments, and period covered;
5. framework requirements this evidence supports, with verified edition, ID, and title;
6. residual evidence and limitations.
Use "supports" or "evidences," never "proves compliance." If an ID cannot be fetched, omit it and
write unverified prose. Do not give legal advice.
```

## Build a control-evidence inventory

```text
Find enforced controls for audit logging, access control, encryption at rest and in transit,
secrets rotation, change management, vulnerability management, and backup/recovery. For each,
produce a row: control -> code/config -> test -> CI/runtime artifact -> owner -> scope -> framework
mapping -> gap. Do not infer a control from policy text or a UI setting.
```

## Audit logging evidence

```text
Trace privileged actions from request to the audit sink. Verify actor, action, target, outcome,
time, request ID, append-only permissions, access logging, retention, and gap detection. Show how
CI tests schema and immutability and how runtime evidence is exported. Then map only the observed
control to ISO/IEC 27001:2022, SOC 2, PCI DSS v4.0.1, HIPAA, GDPR, OWASP Top 10:2025, ASVS 5.0.0,
and CWE. Never invent granular criteria.
```

## Access control evidence

```text
Locate server-side authorization and identity configuration. Try direct object access, stale
roles, orphaned identities, and policy-service failure. Identify the negative tests, deployed
policy digest, identity-provider access review export, and remediation proof. Map the control
technical-control first; a hidden button and a signed policy are not enforcement evidence.
```

## Encryption evidence

```text
Find every storage and network trust boundary in scope. Confirm encryption is explicit in IaC,
key use is restricted, TLS certificate verification is enabled, and production state is queried
for drift. Produce the evidence contract. Distinguish encryption at rest, transmission security,
and key governance before mapping them.
```

## Secrets rotation evidence

```text
Trace how <workload> obtains, refreshes, and revokes credentials. Do not print secret values.
Verify expiry, bounded overlap, failed-old-version behavior, emergency rotation, and audit events.
Define a metadata-only CI/runtime artifact, then map the implemented behavior to verified
framework titles and state what remains unverified.
```

## Change management evidence

```text
For one production deployment, link requested change, independent approval, source commit, CI
tests, immutable artifact digest, deploy identity, environment, and rollback. Prove that a failed
security gate or missing approval blocks deployment. Map to the frameworks only after showing the
enforcement path.
```

## Vulnerability management evidence

```text
Read the SAST, SCA, container, SBOM, and IaC scan workflows. Verify scanners can fail the build,
exceptions expire, results include tool/rules/database metadata, and remediation is traceable.
Cross-link skills/core/devsecops/. Return mappings for the actual scan coverage, not generic
vulnerability-management claims.
```

## Backup and recovery evidence

```text
Do not stop at backup job status. Locate the backup policy, encryption, access control, restore
job, integrity check, dependency recovery, measured recovery point/time, and restored-data
destruction. Map the demonstrated backup and restore capabilities separately. Flag any use of
production data in an uncontrolled test environment.
```

## CI evidence pipeline

```text
Design one CI evidence manifest for this repository. Include SBOM, dependency scan, SAST, image
scan, IaC policy result, authorization negative tests, audit schema tests, provenance, and safe
runtime exports. Bind every artifact to commit and build digest; record tool and policy versions;
sign the manifest; set access and retention. Use patterns from skills/core/devsecops/. Do not
include credentials or raw personal data.
```

## Disprove a claimed control

```text
The control owner claims <claim>. Try to disprove it. Compare policy, implementation, deployed
state, negative tests, and operating evidence. Look for fail-open errors, unscoped resources,
manual bypasses, non-blocking CI, stale screenshots, and gaps in the observation period. Report
the concrete technical gap even if audit paperwork passed.
```

## Review a mapping table

```text
Review this mapping table for backwards reasoning, invented IDs, edition drift, scope ambiguity,
duplicate manual mappings, and artifacts that establish only design rather than operation. For
each bad row, rewrite it as technical control -> evidence -> framework requirement -> limitation.
Fetch every cited requirement title or remove the ID.
```

## Generate an access-review artifact

```text
From the identity-provider export schema, design a minimised access-review artifact containing
stable subject ID, role, grant source, last use, owner, reviewer decision, decision time,
remediation status, and exception expiry. Exclude credentials and unnecessary personal data.
State how completeness, reviewer independence, and removal are verified.
```

## Report format

```text
For every finding return:
- Control and location
- Failure/abuse path
- Enforcement status: documented / implemented / tested / operating
- Evidence artifact, scope, period, and collection method
- Verified mappings: framework edition, ID, exact title, source URL, checked date
- Unverified mappings in prose, with no invented ID
- Remediation and why it closes the enforcement or evidence gap
- Residual limitation and auditor/legal decision needed
```

## Anti-patterns

| Prompt | Why it fails | Better direction |
|---|---|---|
| "Make us compliant with ISO and SOC 2" | No scope; asks for an impossible certification claim | Name a deployed control and map its evidence |
| "Give me every requirement ID" | Encourages recalled or invented identifiers | Fetch only requirements touched by observed controls |
| "Fill this compliance checklist" | Runs framework-to-assertion and hides missing enforcement | Trace code/config to tests and artifacts first |
| "Take screenshots for the audit" | Point-in-time, manual, weak provenance | Export machine-readable state through CI or a scheduled job |
| "Say encryption is enabled" | Omits boundary, algorithm, keys, assets, and runtime drift | Verify IaC plus deployed state and negative TLS tests |
| "Prove our backups work" | Backup success is not recovery | Perform isolated restore, integrity check, and objective measurement |
| "Show the secret was rotated" | May leak values and ignores revocation | Export metadata and prove the prior version fails |
| "Map this policy to PCI" | Policy is not technical operation | Locate enforcement and operating evidence, then map |
| "Use the most likely control number" | A wrong ID is worse than omission | Mark prose unverified until the publisher source is fetched |
| "The audit passed, close the issue" | Audit sampling can miss an exploitable gap | Test the prohibited action and fix enforcement |

## Guardrail suffix

Append this to any compliance prompt:

```text
This work is engineering evidence mapping, not legal advice or certification. The auditor's
interpretation governs. Do not invent requirement IDs, versions, titles, or dates. Fetch the
publisher source; if unavailable, omit the ID and label the prose unverified. Use synthetic data
and never expose secrets in evidence.
```
