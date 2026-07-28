# DevSecOps Prompt Examples

Good prompts name the delivery stage, trust boundary, available authority, and desired output. "Add
DevSecOps" produces a pile of scanners; asking what blocks and why produces a pipeline.

## Audit GitHub Actions for exploit paths

```text
Read every workflow under .github/workflows. For each job identify its trigger, untrusted inputs,
GITHUB_TOKEN permissions, secrets, runner type, and third-party actions. Report only findings with
an exploitation path. Prioritize pull_request_target plus PR checkout, mutable action refs,
over-broad permissions, long-lived cloud keys, and artifacts crossing into privileged jobs. Map
each finding to OWASP A03/A08, ASVS V13/V15, and CWE-829 or CWE-506.
```

Why it works: it models authority and attacker influence together. Searching only for the word
`secret` misses the repository token and OIDC permissions.

## Design scanner placement

```text
Inventory the languages, package managers, IaC, containers, and deployed web surfaces in this
repository. Propose SAST, SCA, secret, IaC, container, licence, and DAST checks. For each one state
what it finds, what it misses, expected false positives, stage, runtime budget, and whether it may
block a merge. The blocking set must be under ten minutes and near-zero false positive.
```

## Baseline an existing repository

```text
We are enabling Semgrep and Trivy on an existing codebase. Design a rollout that can absorb 4,000
historical findings without making main permanently red. Define the baseline format, initial
triage, changed-code gate, owners, burn-down metrics, suppression review, and the criteria for
promoting a rule from advisory to blocking.
```

## Review a dependency update as code

```text
Review this dependency update and lockfile diff as executable code. Check package ownership,
install scripts, new transitive dependencies, licence changes, known advisories, and which runtime
paths use the updated component. State whether it fits our auto-merge policy: patch updates of dev
dependencies only. Do not infer safety from semver alone.
```

## Add OIDC deployment

```text
Replace the stored cloud access key in this GitHub Actions deployment with OIDC federation. Keep
id-token: write only on the deploy job. Provide the workflow change and the cloud trust conditions
for exact repository, protected environment or ref, audience, and least-privilege role. Explain
which long-lived secrets can be deleted after verification.
```

## Build SBOM and provenance

```text
Modify the release pipeline to generate a CycloneDX or SPDX SBOM during the build from the exact
container image, sign the image with cosign, produce platform provenance, and bind all evidence to
one digest. Add an admission-time verification policy for expected issuer and workflow identity.
Do not call an SBOM a vulnerability report.
```

## Triage scanner findings

```text
Triage these SCA findings using the shipped artifact, dependency scope, vulnerable-function
reachability, attacker-controlled input, exposure, exploit maturity, and blast radius. Preserve
vendor CVSS and add a contextual severity with evidence. Assign an SLA and require any exception
to have owner, approver, compensating control, and expiry.
```

## Verify the proposed gate

```text
Run skills/core/devsecops/checklist.md against the pipeline change. Mark each applicable item pass,
fail, or unverified. Confirm action refs are full commit SHAs, job permissions are minimal, fork PRs
receive no secrets, artifact digests are checked, and blocking checks are fast and precise. Do not
claim branch protection is active from workflow YAML alone.
```

## Prompt Anti-Patterns

| Prompt | Problem | Better direction |
|---|---|---|
| "Add security scanning" | No tool class, stage, or failure policy | Name surfaces; require placement and blocking decision |
| "Make CI secure" | No trust boundary or platform | Inventory triggers, token scopes, secrets, runners, actions |
| "Fail on all highs" | Scanner severity ignores reachability and noise | Define exploitability and rule precision |
| "Use best-practice permissions" | Does not say what each job needs | Ask for a job-by-job permission table |
| "Make us SLSA compliant" | SLSA has tracks and levels; no target stated | Choose Build L2 or L3 and ask for evidence gaps |
| "Generate an SBOM" | May inventory source after the build | Require build-time generation from the shipped digest |
| "Auto-merge dependency updates" | Scope is dangerously broad | Limit to patch updates of dev dependencies after required checks |
| "Scan the Dockerfile for CVEs" | Dockerfile is not the built image | Scan IaC/config at PR time and image by digest after build |
| "Mask every secret" | Masking is log rendering, not containment | Prevent secret values from reaching logs or untrusted steps |
| "Accept this risk" | Permanent unowned waiver | Require evidence, owner, approver, control, expiry |
