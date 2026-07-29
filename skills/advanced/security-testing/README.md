# Security Testing Skill

Tests that fail when the vulnerability is present, run where they keep working.

## Purpose

Most security test suites are decorative. They send a payload, assert the response is not a
500, and pass equally well on the fixed and the unfixed code. The suite grows, the coverage
number rises, and the next IDOR ships anyway.

This skill gives an assistant a way to write tests with a provable property: the test fails on
the pre-fix code. It also covers the layer choice that decides whether the test survives a
refactor, the CI gating policy that decides whether it stays enabled, and the triage step that
decides whether a scanner result is a finding at all.

Scope authorization is treated as a precondition, not an appendix. Active testing against a
system you do not own is not in scope for this skill under any framing.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, works the six-step workflow,
and opens the supporting file for the step it is on.

```text
SKILL.md                   scope rules, workflow, layer table, CI gating, entry point
README.md                  this file
checklist.md               pre-return verification for a test suite
best-practices.md          test patterns, weak/strong pairs, test-data safety, CI
common-mistakes.md         tests that pass on vulnerable code, and why
troubleshooting.md         flakiness, blocked scope, wrong gates, unreproducible results
prompts.md                 prompts per testing task, plus anti-patterns
references/
  wstg-4.2.md              WSTG v4.2 categories and the test IDs used here
  asvs-5.0.md              chapter map, levels, how to cite in a test name
  owasp-top10-2025.md      categories, and what testing each one implies
  cwe-mapping.md           weakness to test-type mapping, with the 2025 Top 25 ranks
examples/
  README.md                eight weak/strong test pairs, each with WSTG ID and CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Web Security Testing Guide | v4.2 (2020-12-03) | 2026-07-28, against the WSTG project page and individual v4.2 test pages |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, against the ASVS project page |
| OWASP Top 10 | 2025 | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP API Security Top 10 | 2023 | 2026-07-28, against `owasp.org/API-Security/` |
| CWE Top 25 | 2025 edition | 2026-07-28, against `cwe.mitre.org/top25/archive/2025/` |

WSTG v4.2 is the current numbered release and dates from December 2020. Version 5.0 is in
development and unreleased; a 4.3 placeholder exists in the repository. Every WSTG ID in this
skill was read from its v4.2 page rather than recalled. WSTG's own guidance is to cite the
versioned form - `WSTG-v42-ATHZ-04` - in external reports, because IDs move between releases;
this skill uses the short form in prose and states the version once.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/advanced/security-testing/SKILL.md` is readable, or copy the `security-testing`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` limits it to read, search,
and web lookup plus `ls`/`cat`; it cannot run a scanner or send a request.

## Example Usage

Turn a fix into a regression test:

```text
I fixed an IDOR in src/api/orders.py by adding an owner filter. Write the regression test
using skills/advanced/security-testing. It must fail on the pre-fix code. Assert the security
property, not the status code alone.
```

Build the matrix:

```text
Build an authorization matrix for the /api/projects resource: anonymous, member, project
admin, org admin, and a user from another org, against read, list, update, delete, and
invite. Then generate parameterized tests from the matrix.
```

Triage a scanner result:

```text
ZAP reported reflected XSS at /search?q=. Tell me how to reproduce it by hand, what would
make it a false positive, and what the test should assert if it is real.
```

More in [prompts.md](prompts.md).

## Limitations

- No test execution. This skill writes tests and pipeline configuration; it does not run
  scanners, send requests, or confirm a test fails on unfixed code. That step is yours, and
  the checklist asks you to do it.
- Examples are Python (pytest, Hypothesis), JavaScript/TypeScript (Jest, Supertest,
  Playwright), and YAML for CI. Nothing here is Go, Rust, C#, Ruby, or JVM specific, though
  the patterns transfer.
- No coverage of memory-safety fuzzing. AFL++, libFuzzer, sanitizer builds, and crash triage
  for C and C++ are a different discipline; six of the 2025 CWE Top 25 are memory-safety
  weaknesses this skill does not address.
- No mobile or thick-client testing. WSTG covers web; MASTG is the mobile equivalent and is
  not summarised here.
- DAST guidance is generic. It names ZAP because its baseline mode is scriptable, but does not
  tune rules for any specific application.
- Business logic flaws remain the hardest to test and the least automatable. A full matrix and
  a clean DAST run say nothing about whether a discount can be applied twice.
- ASVS mapping is at chapter level (V1 to V17), not requirement IDs. For formal ASVS
  verification, work from the official repository.
- A green suite is evidence, not proof. State what was not tested.

## Security Notes

This skill contains deliberately weak tests and vulnerable code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Weak tests are labelled `Weak:` and vulnerable code
`Vulnerable:`; each is paired with a stronger version. Do not copy a labelled-weak block into
a suite.

Payloads in the examples are the minimum needed to make a test meaningful, and they target the
example application only. They are not tooling for use against systems you do not own.

Test fixtures use placeholder identities (`alice`, `bob`, `example.com`, `attacker.example`).
There are no real credentials, hostnames, or personal data in this skill, and
[best-practices.md](best-practices.md#test-data-safety) explains why production data must not
appear in a test suite.

## References

- OWASP Web Security Testing Guide v4.2 - <https://owasp.org/www-project-web-security-testing-guide/v42/>
- OWASP WSTG project page - <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- CWE Top 25 (2025) - <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- OWASP Cheat Sheet Series - <https://cheatsheetseries.owasp.org/>
