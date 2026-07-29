# Security Tooling Matrix

Verified 2026-07-28. Product names are examples. The tool class matters more than the vendor.

| Tool class | Examples | What it actually finds | What it does not establish | Best stage | False positive profile | Merge gate? |
|---|---|---|---|---|---|---|
| SAST | CodeQL, Semgrep | Code patterns and data flows: injection sinks, unsafe APIs, missing guards, language-specific defects | Runtime configuration, deployed routes, business intent, actual reachability in every dynamic language | Fast rules pre-commit; changed-code PR; deeper interfile nightly | Semgrep syntax rules can be low-noise when narrow; broad patterns are noisy. CodeQL dataflow is deeper but modelling gaps and query packs vary | Only reviewed high-confidence rules on changed code |
| DAST | ZAP | Observable running behaviour: headers, reflected input, auth/session mistakes, exposed paths, some injections | Unreached endpoints, source-only flaws, exact root cause, business logic without a scripted flow | Isolated environment nightly or pre-release | Medium to high until authentication, crawl scope, and passive/active rules are tuned; transient responses add noise | Rarely. Only deterministic regression assertions, not a broad crawl |
| SCA | Dependabot alerts, Renovate plus advisory source, osv-scanner, ecosystem audit tools | Known advisories matched to resolved dependency versions; sometimes licence and reachability data | Unknown vulnerabilities, malicious packages without an advisory, vendored binaries, exploitability unless reachability is modelled | Lockfile changes on PR; full graph daily as advisories change | Version matching is low-noise for presence, but severity without reachability is often misleading. Alias and distro backport data can be wrong | Block newly introduced reachable issues under policy; do not block all historical highs |
| Secret scanning | Gitleaks, platform push protection | Credential-shaped strings, known token formats, entropy and custom patterns in diffs/history | Whether a generic string is live, secrets split/encoded at runtime, credentials outside scanned stores | Staged diff pre-commit; push protection; full history/nightly | Known provider patterns are low-noise; entropy and generic patterns can be high-noise | Yes for verified provider patterns and tested custom rules |
| IaC scanning | Checkov, tfsec, Trivy config | Misconfiguration patterns in Terraform, Kubernetes, CloudFormation, Dockerfiles, and related policy files | Deployed drift, runtime IAM context, compensating controls outside the file | PR on changed IaC; periodic scan of repositories and deployed state | Medium. Context-free rules often flag intentional public resources or miss module/variable resolution | Only selected rules tied to policy. Baseline existing resources |
| Container scanning | Trivy, Grype | OS and language packages found in an image, known CVEs, sometimes secrets/misconfiguration and SBOM output | Runtime exploitability, kernel/host state, packages removed from metadata, unknown malicious code | Built image by digest before publish; rescan registry nightly | Package presence is usually precise; distro backports, version parsing, and severity remain noisy | Block newly introduced reachable critical/high under explicit policy |
| Licence compliance | ScanCode, ORT, FOSSA, SCA licence features | Declared and detected licences, notices, dependency graph, policy conflicts | Definitive legal interpretation, obligations for every mixed/dual-licensed work, provenance of copied snippets unless scanned | Dependency change PR; release evidence | Medium. `UNKNOWN`, conflicting metadata, generated code, and dual licensing require review | Block explicit deny-list hits; route unknown/custom/conflicts to review |
| SBOM generation | Syft, CycloneDX plugins, SPDX tooling | Component inventory, versions, dependency relationships, identifiers and licences for an artifact | Vulnerability status, absence of malicious code, build integrity, legal compliance | During build, from exact artifact | Not a finding tool. False negatives come from opaque binaries and incomplete package metadata | Generation can block releases; SBOM contents need quality checks |

## Placement Rules

`A03:2025` · `A08:2025` · ASVS V13, V15 · NIST SSDF PW.5

- Pre-commit: deterministic, changed-file checks under five seconds. Secret patterns, format, and
  narrow Semgrep rules. Developers may bypass local hooks, so repeat security checks server-side.
- PR: checks needing repository context but still under ten minutes. Changed-code SAST, lockfile
  SCA, IaC, licence policy, unit/integration security tests.
- Build/release: evidence about the exact artifact. Image scan, SBOM, digest, signature,
  provenance. Keep build and publish authority separate where possible.
- Nightly/weekly: analysis whose cost or variability makes it a bad gate. Full CodeQL packs,
  authenticated ZAP, registry rescans, full history secret scan, fuzzing.

A gate that blocks a merge must be fast and near-zero false positive, or it will be disabled. A
noisy rule belongs in advisory mode until tuned. An important but slow check belongs after the PR
or on a schedule with an enforced remediation process.

## Tool-Specific Notes

### CodeQL and Semgrep

CodeQL's strength is semantic/dataflow analysis across a codebase. Its cost is build setup for
compiled languages, query runtime, and model coverage. Semgrep is fast for local syntactic and
intrafile patterns; Pro/interfile modes change that profile. Neither scanner proves exploitability.
Use a baseline commit or stable fingerprints so existing findings do not block every PR.

### ZAP

Start with passive/baseline scanning against an isolated deployment. Active rules send attack
payloads and can change data. Script authentication and seed state before interpreting coverage.
DAST false negatives are common when the crawler never reaches a route.

### SCA

Scan the resolved graph, not only manifests. Re-run periodically because a clean version today can
receive an advisory tomorrow. Treat a package update as executable code: npm lifecycle scripts,
pip build backends, Gradle/Maven plugins, and similar hooks execute during install/build (CWE-829).

### Checkov and tfsec

Both inspect IaC source. tfsec remains available, but Aqua states engineering attention has moved
to Trivy and encourages migration. Do not start a new long-lived policy solely on tfsec without a
migration plan. Checkov and Trivy policy IDs differ; preserve policy intent, not tool-specific IDs.

### Trivy

Scan the final image by digest after all build stages. A source/lockfile scan cannot see OS
packages or files copied into the image; a Dockerfile scan cannot know the exact installed package
versions. Rescan stored digests as advisory data changes.

### Licence Scanning

Automate clear policy: approved permissive licences may pass; explicit prohibited licences may
block; unknown, dual, custom, or conflicting declarations need human review. A scanner result is
input to legal review, not legal advice.

## References

- OWASP A03 and A08 - <https://owasp.org/Top10/2025/>
- NIST SSDF PW.5 (secure code practices) and PW.8 (testing) - <https://csrc.nist.gov/pubs/sp/800/218/final>
- Semgrep rules - <https://docs.semgrep.dev/writing-rules/rule-syntax>
- CodeQL - <https://codeql.github.com/docs/>
- ZAP - <https://www.zaproxy.org/docs/>
- Trivy - <https://trivy.dev/>
- Checkov - <https://www.checkov.io/>
- tfsec status - <https://github.com/aquasecurity/tfsec>
- CycloneDX - <https://cyclonedx.org/>
- SPDX - <https://spdx.dev/>
