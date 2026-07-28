---
name: devsecops
description: 'Design and review security in the CI/CD pipeline — what scanners run, when they run, and what blocks a merge. Covers SAST, DAST, SCA, secret and IaC scanning, SBOM, SLSA provenance, GitHub Actions hardening, and vulnerability SLAs. Triggers: "CI/CD security", "pipeline", "GitHub Actions", "SBOM", "supply chain", "pre-commit", "SLSA", "bảo mật CI", "chuỗi cung ứng".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# DevSecOps

Security controls that live in the pipeline. Two questions decide everything here: what runs
at which stage, and what is allowed to block a merge.

## When to Use

- Adding or reviewing a scanner in CI (SAST, DAST, SCA, secrets, IaC, containers)
- Writing or auditing a GitHub Actions workflow, especially one with secrets
- Setting up dependency automation (Dependabot, Renovate) and deciding what auto-merges
- Generating an SBOM, signing artifacts, or verifying provenance at deploy time
- Defining vulnerability SLAs, triage rules, and exception handling
- Investigating why nobody trusts the security gate any more

## The One Rule That Decides the Rest

A check that blocks a merge must be fast and near-zero false positive. Everything else runs
where a human can ignore it without stopping work.

This is not a preference. A blocking gate with a 30 percent false positive rate gets
`--no-verify`, `continue-on-error: true`, or an admin bypass within two sprints, and then the
signal is gone along with the noise. Choose what blocks deliberately and keep that set small.

| Stage | Budget | Blocking? | Typical checks |
|---|---|---|---|
| Pre-commit | under 5s | yes, locally | secret scan on staged diff, format, lint |
| Pre-push | under 60s | yes, locally | unit tests, quick SAST on changed files |
| PR | under 10min | only the precise checks | SAST diff scan, SCA on lockfile change, IaC scan, licence check |
| Merge to main | minutes | no, alerts | full SAST, SBOM, sign, provenance |
| Nightly / weekly | hours | no, tickets | DAST, full dependency tree, container base image rescan, fuzzing |

## Workflow

### 1. Inventory what already runs

Read the workflow files before proposing anything. Check `.github/workflows/`, `.gitlab-ci.yml`,
`.pre-commit-config.yaml`, `renovate.json`, `.github/dependabot.yml`. Note which jobs carry
`continue-on-error`, `|| true`, or a soft-fail flag — those are checks someone already gave up on,
and the reason matters more than adding a new tool.

### 2. Match tool class to what you actually need found

One tool class per failure mode. See [references/tooling-matrix.md](references/tooling-matrix.md)
for what each class finds, what it structurally cannot find, and its false positive profile.

A short version: SAST finds code patterns and misses runtime config. DAST finds runtime
behaviour and misses unreachable code paths. SCA finds known CVEs in declared dependencies and
misses vendored code. Nothing finds business logic flaws.

### 3. Place each check at the cheapest stage that can catch it

Shift left means catch it where it costs least, not run everything everywhere. A secret scan on
the staged diff costs 200ms and prevents a rotation incident; the same scan over full history
costs minutes and belongs nightly.

### 4. Baseline before enforcing

A new tool on an existing codebase produces hundreds to thousands of findings. Record them as a
baseline, fail only on new findings, and burn the baseline down on a schedule. See
[best-practices.md](best-practices.md#baselining-an-existing-codebase). Skipping this step is the
most common way a rollout dies.

### 5. Harden the pipeline itself

The pipeline is the highest-value target in the repository: it holds cloud credentials, it can
push to production, and it executes code from pull requests. Treat a workflow file as
security-critical code. `permissions:` at job level, third-party actions pinned to a commit SHA,
OIDC instead of stored cloud keys, and never `pull_request_target` with a checkout of the PR head.
See [best-practices.md](best-practices.md#cicd-pipeline-security).

### 6. Close the loop

A finding with no owner, no SLA, and no expiry date on its exception is not managed, it is
recorded. See [best-practices.md](best-practices.md#vulnerability-management).

## Severity

Rank by exploitability in this deployment, not by the CVSS number the scanner printed.

- Critical — pipeline compromise (secret exfiltration from a fork PR, unpinned action in a job
  with a write token), or an RCE in a reachable dependency on an internet-facing service
- High — a stored long-lived cloud credential, a write-scoped `GITHUB_TOKEN` on a job that runs
  untrusted code, an exploitable CVE in code that executes
- Medium — a CVE in a dependency that is present but not reachable, a missing SBOM, an unsigned
  artifact where verification is not yet enforced
- Low — defence in depth missing with no path: unpinned first-party action, missing licence scan

Reachability changes the answer more than anything else. A critical CVSS in a transitive
dependency that no code path calls is not a critical finding, and saying otherwise is how a
backlog reaches four thousand items nobody reads. State which way you called it and why.

## Standards This Maps To

| Concern | Standard |
|---|---|
| Dependency and build path integrity | OWASP Top 10 2025 A03 Software Supply Chain Failures |
| Unsigned artifacts, CI trusting unverified input | OWASP Top 10 2025 A08 Software or Data Integrity Failures |
| Secure coding and architecture requirements | OWASP ASVS 5.0 V15 |
| Build, deploy, and secret configuration | OWASP ASVS 5.0 V13 |
| Secure development practices at process level | NIST SP 800-218 SSDF 1.1 (PO, PS, PW, RV) |
| Build platform integrity and provenance | SLSA v1.2 Build track L0 to L3 |
| Unmaintained components | CWE-1104 |
| Malicious code in the supply chain | CWE-506 |
| Executing code from an untrusted source | CWE-829 |

## Related Skills

- `supply-chain-security` — dependency provenance and registry trust in depth
- `secrets-management` — storage, rotation, and detection of credentials
- `docker-security` — container image and runtime hardening
- `cloud-security` — the IAM side of OIDC federation
- `owasp` — the application-level controls this pipeline is checking for
- `publish-safety` — the manual gate at the publish boundary, where no pipeline is watching

## Supporting Files

- [README.md](README.md) — purpose, layout, limitations, security notes
- [checklist.md](checklist.md) — pre-return verification
- [best-practices.md](best-practices.md) — patterns, with vulnerable and hardened workflows
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/](references/) — tooling matrix, SLSA levels, SSDF, OWASP mapping
- [examples/](examples/) — eight vulnerable/fixed pairs, plus runnable workflow, pre-commit,
  and Semgrep files
