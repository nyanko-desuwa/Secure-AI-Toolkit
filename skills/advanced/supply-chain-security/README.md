# Supply Chain Security Skill

Guidance for deciding how dependencies, builds, and artefacts are trusted, mapped to OWASP
`A03:2025` and `A08:2025`, ASVS 5.0 V13 and V15, NIST SSDF, and SLSA.

## Purpose

Most of the code in a deployed application came from somewhere else. This skill covers the
process that put it there - dependency selection and maintenance signals, resolution, retrieval,
install-time execution, build, distribution, and update - and what to verify at each step. It
exists so an assistant can say "this resolves internal names against a public index, which is ASVS
15.2.4 and A03" instead of "consider using trusted dependencies".

A03:2025 is new in the 2025 Top 10. It was promoted because supply-chain failure is broader than
known-vulnerable libraries: the community survey put it first, exactly 50% ranked it #1, and the
published data found the category had the highest average incidence while only 11 CVEs mapped to
its CWEs. Compromised build processes, registries, install scripts, and artifacts do not usually
have CVE identifiers. It descends from the old "Using Components with Known Vulnerabilities"
lineage, but is not a 2021 renumbering. A03 names the chain; A08 covers consuming unverified
software or data.

## How It Works

Plain Markdown, nothing executes. An assistant reads `SKILL.md`, walks the six trust links
(resolution, retrieval, install, build, distribution, update), and pulls in the supporting
file for the link it is working on.

```text
SKILL.md                        trust links, workflow, severity, entry point
README.md                       this file
checklist.md                    pre-return verification, grouped by trust link
best-practices.md               patterns, vulnerable/fixed pairs
common-mistakes.md              what goes wrong and why the fix works
troubleshooting.md              when the guidance cannot be applied
prompts.md                      prompts that produce findings, plus anti-patterns
references/
  owasp-a03-a08-2025.md         both categories, mapped CWEs, published scenarios
  asvs-v13-v15.md               requirement text for the ones that apply here
  slsa.md                   Build track levels, in-toto, Sigstore/cosign
  sbom-formats.md               CycloneDX versus SPDX, actual uses and limits
  incident-patterns.md          event-stream, ua-parser-js, xz, Codecov, PyPI, slopsquatting
  nist-ssdf-1.1.md              practice groups and the cross-standard mapping
  ecosystem-controls.md         npm, pip, Go, Java, containers - verified flags
examples/
  README.md                     eight vulnerable/fixed pairs, package and CI
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 (A03, A08) | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, against the ASVS repository |
| SLSA | v1.2, status Approved | 2026-07-28, against `slsa.dev/spec/v1.2/` |
| NIST SSDF | SP 800-218 v1.1 (February 2022) | 2026-07-28, against `csrc.nist.gov` |
| CycloneDX | 1.7 (2025-10-21), ECMA-424 (2025-12-10) | 2026-07-28, against the OWASP project page |
| SPDX | 3.0 listed current; specification site serves 3.0.1 | 2026-07-28, against `spdx.dev` and the 3.0.1 specification |

CWEs cited: CWE-829, CWE-345, CWE-347, CWE-494, CWE-1104, CWE-1357, CWE-1395.

Ecosystem tool flags carry their own verification dates in
[references/ecosystem-controls.md](references/ecosystem-controls.md), because they change far
faster than the standards do.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/advanced/supply-chain-security/SKILL.md` is readable, or copy the
`supply-chain-security` directory into `~/.claude/skills/`. The frontmatter `allowed-tools`
restricts it to read, search, and web lookup plus `ls` and `cat`.

## Example Usage

Review a lockfile change with the actual risk question attached:

```text
Review the dependency changes in this diff against OWASP A03:2025. For each added or
upgraded package: is it pinned with a hash, does it run install scripts, and is it
reachable from a request path? Skip packages that are only version bumps of existing deps.
```

Audit the release pipeline:

```text
Read .github/workflows/release.yml and map it to SLSA v1.2 build levels. What level does it
reach today, what is the single change that raises it, and where could a fork PR reach a
secret?
```

Triage without theatre:

```text
We have 47 findings from the SCA scan. Group them by reachability from a request path, not
by CVSS. For each group, give the remediation window from
skills/advanced/supply-chain-security/best-practices.md and state how you judged
reachability.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a scanner. It cannot tell you whether a specific package version is
  malicious, and it has no vulnerability database. Pair it with SCA and a registry firewall.
- Reachability analysis is the load-bearing part of triage and it needs call-graph tooling to
  do properly. This skill tells you to state your reasoning; it cannot compute the answer.
- Ecosystem coverage is npm, pip, Go, Maven and Gradle, and container images. Nothing here is
  specific to Cargo, NuGet, RubyGems, Composer, or Bazel, though the six trust links apply
  unchanged.
- The CI examples are GitHub Actions. GitLab CI, Jenkins, and Buildkite have the same failure
  shapes with different syntax; `pull_request_target` in particular has no direct equivalent.
- SLSA levels are described from the specification. A claim of Build L3 depends on the build
  platform's implementation, which reading a workflow file cannot confirm.
- No attestation-format authoring guidance beyond attaching what the tooling generates. If you
  need to write in-toto predicates by hand, go to the in-toto specification.
- Says nothing about legal or licence compliance. An SBOM serves both purposes; only the
  security half is covered here.
- Vendoring is covered only as a dependency-trust tradeoff: record upstream source, version,
  hashes, and advisory ownership. Patch management and licence obligations for a maintained
  fork need their own review.
- Historical mechanisms are limited to incidents with sources verified in
  `references/incident-patterns.md`. It does not attempt a complete chronology, and it states
  plainly where an advisory omits payload details.

## Security Notes

This skill contains deliberately vulnerable configuration in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` or marked as
the vulnerable half of a pair. Do not copy one into a project.

Registry hostnames, package names, image references, and identity strings are placeholders.
Real incidents named in [references/incident-patterns.md](references/incident-patterns.md) and
[references/owasp-a03-a08-2025.md](references/owasp-a03-a08-2025.md) are named deliberately,
with the mechanism and source attached rather than an exploit payload.

Commit-SHA pins in the examples are illustrative. Resolve the real SHA for the version you
want before using one - a wrong pin is a broken build, and copying a pin from documentation is
how you end up trusting a commit nobody reviewed.

## References

- OWASP Top 10 2025 A03 - <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>
- OWASP Top 10 2025 A08 - <https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- SLSA - <https://slsa.dev/spec/v1.2/>
- NIST SP 800-218 - <https://csrc.nist.gov/pubs/sp/800/218/final>
- Sigstore documentation - <https://docs.sigstore.dev/>
- OpenSSF Scorecard - <https://github.com/ossf/scorecard>
- CycloneDX - <https://owasp.org/www-project-cyclonedx/>
- SPDX - <https://spdx.dev/use/specifications/>
- PyPA PEP 708 - <https://peps.python.org/pep-0708/>
- Sigstore cosign - <https://docs.sigstore.dev/cosign/>
