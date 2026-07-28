# DevSecOps Skill

Security gates fail in two ways: they miss a real issue, or they become noisy enough that the
team disables them. This skill designs the pipeline around both failure modes.

## Purpose

Give an AI assistant a concrete way to decide what security check runs at each point in the
software delivery lifecycle, what may block a merge, and what evidence must follow a release.
Every control maps to OWASP Top 10 2025 A03/A08, ASVS 5.0 V13/V15, NIST SSDF, SLSA, or a CWE.

## How It Works

The skill is Markdown guidance plus runnable configuration examples. Nothing in this directory
executes automatically. The assistant inventories the existing pipeline, maps each requested
check to the failure it can detect, chooses a stage based on cost and signal quality, baselines
existing findings, hardens workflow permissions, then defines triage and expiry.

```text
SKILL.md                            entry point, workflow, severity
README.md                           this file
checklist.md                        pre-return verification
best-practices.md                   patterns with vulnerable/fixed pairs
common-mistakes.md                  rollout and pipeline failures
troubleshooting.md                  conflicts and constrained environments
prompts.md                          prompts and anti-patterns
references/
  owasp-asvs.md                     A03, A08, ASVS V13/V15, CWE mapping
  nist-ssdf.md                      SP 800-218 practice groups
  slsa-levels.md                    SLSA v1.2 Build L0-L3
  tooling-matrix.md                 scanners by finding, stage, and noise
examples/
  README.md                         eight vulnerable/fixed pairs
  vulnerable-pr-target.yml          deliberately vulnerable workflow
  hardened-pr.yml                   hardened PR gate
  release-signed.yml                SBOM, signing, and provenance example
  pre-commit-config.yaml            fast local checks
  semgrep-rule.yml                  workflow supply-chain rule
```

## Standards Covered

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A03 and A08 risk categories | 2026-07-28 |
| OWASP ASVS | 5.0.0 | V13 and V15 chapters | 2026-07-28 |
| NIST SSDF, SP 800-218 | 1.1, February 2022 | PO, PS, PW, RV practices | 2026-07-28 |
| SLSA | 1.2, Approved | Build provenance and platform levels | 2026-07-28 |
| CycloneDX | 1.7 | SBOM serialization | 2026-07-28 |
| SPDX | 3.0; ISO/IEC 5962:2021 covers SPDX 2.2.1 | SBOM and licence data | 2026-07-28 |
| CWE | current definitions | CWE-1104, CWE-506, CWE-829 | 2026-07-28 |

The skill cites ASVS at chapter level. It does not invent individual requirement IDs. Formal
ASVS verification must use the official 5.0.0 requirement set.

## Configuration

Copy the files you need; do not install all of them blindly.

1. Copy `examples/pre-commit-config.yaml` to `.pre-commit-config.yaml`. Review every pinned
   revision, then run `pre-commit install`.
2. Copy `examples/hardened-pr.yml` under `.github/workflows/`. Adapt languages, paths, and lockfile
   commands. Replace every example action commit with a reviewed current commit when updating.
3. Put `examples/semgrep-rule.yml` under a Semgrep config directory and test it against known-safe
   and known-unsafe workflow fixtures before making it blocking.
4. Enable branch protection or a ruleset. Require the named PR job, one or more reviews, and
   conversation resolution. A required workflow without protected branches is advisory.
5. Configure cloud trust for the repository and environment before enabling OIDC. The workflow's
   `id-token: write` permission only permits requesting an OIDC token; the cloud role's trust
   policy decides what it can become.

GitHub Actions examples pin third-party actions to full commit SHAs and leave a release comment.
Tags are readable but mutable. When an action needs an update, inspect its release and diff, then
replace the SHA. Dependency automation can open that change, but a human should review actions
that receive secrets or a write token.

## Dependency Policy

Commit one lockfile per package manager and install from it (`npm ci`, `pip --require-hashes`,
`cargo --locked`, or the ecosystem equivalent). Pin direct dependencies and the build toolchain.
A dependency update is a code change: package install hooks and build plugins execute during CI
and often on developer laptops (CWE-829).

Automation should open small, frequent updates. Automatic merge is deliberately narrower:
patch updates of development dependencies only, after all required checks pass. Do not
implicitly expand it to production dependencies, minor versions, majors, GitHub Actions, Docker
base images, or digest changes. See [best-practices.md](best-practices.md#dependency-management).

## Example Usage

```text
Review every file in .github/workflows. For each finding report file:line, the untrusted input,
token or secret available to the job, exploitation path, and the smallest fix. Apply OWASP
A03/A08 and CWE-829. Do not report style issues.
```

```text
Design a staged rollout for Semgrep, dependency scanning, Trivy, and ZAP on this repository.
Inventory existing findings, propose a baseline, and identify exactly which checks may block a
pull request. Keep the blocking path under ten minutes.
```

More task-specific prompts are in [prompts.md](prompts.md).

## Limitations

- Scanner names are examples, not endorsements. Tool behaviour and licences change. Validate the
  installed version and ruleset before relying on a result.
- SAST cannot prove a runtime path is reachable. DAST cannot cover code paths it does not drive.
  SCA depends on vulnerability databases and package metadata. None replaces threat modelling or
  review of business logic.
- A clean scan is not evidence that a build is trustworthy. Provenance says how an artifact was
  built; it does not say the source was safe.
- An SBOM is an inventory, not a vulnerability report and not proof of licence compliance. It
  becomes useful when incident response asks "do we ship component X?" or a customer needs the
  exact transitive dependency set.
- Licence classification has legal consequences. A scanner can identify declared licences and
  conflicts; legal counsel decides obligations and exceptions.
- The GitHub examples do not cover GitLab, Azure Pipelines, Jenkins, or every cloud. The principles
  apply; the syntax does not.
- Self-hosted runners cannot be made safe for arbitrary public fork code merely by cleaning the
  workspace. Use ephemeral isolated runners or GitHub-hosted runners for untrusted contributions.
- Reproducible builds are not feasible in every ecosystem. Record non-deterministic inputs,
  eliminate them incrementally, and keep signed provenance even when bit-for-bit reproduction is
  not yet possible.

## Security Notes

This directory contains deliberately vulnerable examples. Every vulnerable block and workflow is
labelled. Never enable `examples/vulnerable-pr-target.yml`; it demonstrates fork-PR secret theft.
The credentials in examples are placeholders only.

A masked secret is not safe to print. Masking is a log rendering feature, not an information-flow
control. Shell tracing, encoding, slicing, exception messages, process listings, artifacts, and
third-party actions can reveal it. Pass secrets only to the step that needs them and never run
untrusted code in that step.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- NIST SP 800-218 — <https://csrc.nist.gov/pubs/sp/800/218/final>
- SLSA v1.2 — <https://slsa.dev/spec/>
- GitHub Actions security — <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- CycloneDX — <https://cyclonedx.org/specification/overview/>
- SPDX — <https://spdx.dev/use/specifications/>
- Sigstore cosign — <https://docs.sigstore.dev/cosign/>
