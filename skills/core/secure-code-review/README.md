# Secure Code Review Skill

A repeatable process for reviewing existing code for security. Same diff, same findings,
twice in a row.

## Purpose

Most security review is a vibe check: read the code, react to keywords, produce a list of
things that look wrong. That list mixes real vulnerabilities with style opinions, so the
author discounts all of it.

This skill fixes that with a fixed order of operations and one hard rule: a candidate finding
must survive an attempt to disprove it before it is reported. Findings that have no
exploitation path are labelled observations and kept out of the count. The value is in what
the review leaves out.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, runs the five-step workflow,
and pulls in the supporting file for whichever step it is on.

```text
SKILL.md                   workflow, sink table, severity matrix, entry point
README.md                  this file
checklist.md               pre-return verification for the review itself
best-practices.md          review patterns, secure refactoring, AI-code review
common-mistakes.md         how reviews go wrong, and the fix
troubleshooting.md         when a finding cannot be confirmed or fixed
prompts.md                 prompts per review type, plus anti-patterns
references/
  review-process.md        the workflow in depth, mapped to the Code Review Guide
  cwe-top25.md             2025 CWE Top 25 ranked, and how to pick a CWE
  owasp-top10-2025.md      categories, and which sinks land in each
  asvs-5.0.md              chapter map for citing a review finding
  cvss-4.0.md              metric groups, and where CVSS misleads
examples/
  README.md                eight worked findings, two of them not vulnerabilities
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP API Security Top 10 | 2023 | 2026-07-28, against `owasp.org/API-Security/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, against the ASVS project page |
| CWE Top 25 | 2025 edition | 2026-07-28, against `cwe.mitre.org/top25/archive/2025/` |
| OWASP Code Review Guide | 2.0 (July 2017) | 2026-07-28, against the project page |
| CVSS | 4.0, spec document v1.2 (2024-06-18) | 2026-07-28, against `first.org/cvss/v4-0/` |

The Code Review Guide 2.0 is the current release and it is old: its vulnerability chapters
are built on the OWASP Top 10 2013. Its process material — reviewer roles, review scoping,
the difference between manual review and scanning — still holds. Take the process from it and
the categories from Top 10 2025.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/core/secure-code-review/SKILL.md` is readable, or copy the `secure-code-review`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` limits it to read,
search, and web lookup plus `ls`/`cat`.

## Example Usage

Review a diff with the disprove step made explicit:

```text
Review the diff against origin/main using skills/core/secure-code-review. Hunt by sink.
For each candidate, try to disprove it before reporting. Report findings and observations
in separate lists.
```

Triage something a scanner flagged:

```text
Semgrep flagged src/reports/export.py:88 as SQL injection. Trace the source and tell me
whether it is exploitable. If it is not, say so and explain what stops it.
```

Review generated code specifically:

```text
This handler was written by an AI. Check the four AI failure modes in
skills/core/secure-code-review/SKILL.md before anything else: auth in the wrong layer,
validation without encoding, fail-open catch, invented API surface.
```

More in [prompts.md](prompts.md).

## Limitations

- No dataflow analysis. This is a reading process, not a taint engine. It will miss
  source-to-sink paths that cross three files and a message queue. Pair it with SAST.
- Cannot see runtime configuration. Whether CSP is actually served, whether the WAF blocks
  the payload, whether the DB user has `FILE` privilege — none of that is in the code. Every
  such assumption must be stated in the finding.
- Severity depends on deployment context the code does not contain. The severity matrix asks
  you to assume internet-facing or internal; a wrong assumption moves a finding two rows.
- ASVS mapping is at chapter level (V1 to V17), not requirement IDs. For formal ASVS
  verification, work from the official CSV.
- The sink table is greppable heuristics for Python, JavaScript/TypeScript, Java, PHP, and
  C#. It is not tuned for Go, Rust, Ruby, or memory-safety review in C and C++. Six of the
  2025 CWE Top 25 are memory-safety weaknesses this skill does not cover.
- Says nothing about business logic flaws that are not weakness classes. A review that finds
  no CWE can still miss a pricing bug. Abuse-case review is a separate exercise.
- CVSS scores produced from code reading alone are Base-only (`CVSS-B`). Threat and
  Environmental metrics need information the reviewer does not have.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md` and `examples/`.
Every vulnerable code block is labelled `Vulnerable:` and paired with a fixed version. The
review anti-patterns in `common-mistakes.md` are labelled as mistakes and followed by a fix. Do
not copy a labelled-vulnerable block into a project.

Two examples are labelled `Not a vulnerability:` — those are safe code shown so a reviewer
learns to recognise a false positive. They are still not drop-in code; they are excerpts.

The examples use placeholder values only. No real credentials, hostnames, or personal data.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Code Review Guide — <https://owasp.org/www-project-code-review-guide/>
- CWE Top 25 (2025) — <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- CVSS v4.0 specification — <https://www.first.org/cvss/v4-0/specification-document>
- OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
