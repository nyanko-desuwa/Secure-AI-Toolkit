# Compliance Skill

Privacy and compliance as implementation work: deletion jobs, consent records, data
inventories, audit evidence, and scope reduction. Not as paperwork.

## Purpose

Two failures happen in opposite directions and both are common.

A control passes the audit and remains exploitable. The access review was signed, the
retention policy was written, the encryption box was ticked — and the deletion endpoint sets
`deleted_at` while the read replica, the nightly backup, the Kinesis stream, and the
warehouse table keep the row intact. The auditor sampled the endpoint's response code.

A system is genuinely secure and fails the audit. Authorization is correct, secrets are in a
manager, TLS is pinned — and there is no append-only record of who granted the admin role,
so nothing can be tested. Auditors evaluate evidence, not code. No artifact means no control.

This skill closes both gaps by naming, for every control, the code that implements it and
the artifact that proves it ran.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the seven-step
workflow (find the data, name the basis, implement the rights, enforce retention, keep PII
out of the exhaust, produce the evidence, verify), and pulls the supporting file it needs.

```text
SKILL.md                        workflow, severity, entry point
README.md                       this file
checklist.md                    pre-return verification, grouped
best-practices.md               patterns with vulnerable/fixed pairs
common-mistakes.md              what goes wrong and why the fix works
troubleshooting.md              when the guidance cannot be applied
prompts.md                      prompts that produce findings
references/
  gdpr-articles.md              article numbers for the rights and duties cited here
  pci-dss-4.md                  version, scope reduction, stored account data
  hipaa-safeguards.md           CFR citations for minimum necessary, audit controls, BAAs
  iso-27001-soc2.md             certification vs attestation, Type II evidence continuity
  nist-privacy-framework.md     Core Functions, and how to map controls onto them
  ccpa-cpra.md                  opt-out preference signal as an implementation
  cwe-privacy.md                CWE-359, 311, 312, 532, 200, 922 with official titles
examples/
  README.md                     seven vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version / citation | Verified |
|---|---|---|
| OWASP Top 10 | 2025 — A01, A02, A04, A09 | 2026-07-28, `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 — V14 Data Protection, V16 Logging and Error Handling, chapter level | 2026-07-28, ASVS project page |
| GDPR | Regulation (EU) 2016/679, article numbers per `references/gdpr-articles.md` | 2026-07-28, `gdpr-info.eu` |
| PCI DSS | 4.0.1 (listed as current in the PCI SSC Document Library) | 2026-07-28, `pcisecuritystandards.org` Document Library |
| HIPAA | 45 CFR Part 164 — §§ 164.312(b), 164.502(b), 164.504(e) | 2026-07-28, `ecfr.gov` |
| ISO/IEC 27001 | 2022 edition | 2026-07-28, see the caveat below |
| SOC 2 | AICPA Trust Services Criteria, five categories | 2026-07-28, `aicpa-cima.com` |
| NIST Privacy Framework | 1.0 final; 1.1 at initial public draft | 2026-07-28, `nist.gov/privacy-framework` |
| CCPA / CPRA | Title 11 CCR § 7001 et seq., effective 2023-03-29 | 2026-07-28, `oag.ca.gov` |
| CWE | 4.20 — CWE-359, 311, 312, 532, 200, 922 | 2026-07-28, `cwe.mitre.org` |

Two honest gaps in that table:

- ISO's own catalogue pages returned HTTP 403 on every attempt from this environment. The
  2022 edition being current is corroborated by secondary sources, but the existence and
  publication date of any amendment to it is unverified here. Check `iso.org` before citing
  an amendment. This skill does not name one.
- PCI DSS 4.0.1 is confirmed as the current version from the SSC Document Library listing.
  The requirement text itself is behind a document download, so this skill cites Requirement
  3 ("Protect stored account data") at requirement level and does not quote sub-requirement
  numbers it could not read.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/enterprise/compliance/SKILL.md` is readable, or copy the `compliance` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search, and web
lookup plus `ls`/`cat`.

## Example Usage

Find every copy of a person's data before promising deletion:

```text
Read the schema and the deletion endpoint. List every place a user's personal data lands:
tables, replicas, log streams, analytics events, third-party calls, and warehouse tables.
For each, say whether our erasure path removes it, expires it, or misses it.
```

Review a new field for minimisation and retention:

```text
This migration adds date_of_birth to the profiles table. What is the purpose, the lawful
basis, and the retention period? If any of the three is unanswerable from the code, say so
and mark it a finding.
```

Check that an audit trail would survive a Type II period:

```text
We are in a SOC 2 Type II observation window. For the admin role-grant path, show me the
control, the evidence artifact, and how a gap in the artifact would be detected. Do not
assume a control runs because the code exists.
```

More in [prompts.md](prompts.md).

## Limitations

Read this section before using anything here in a regulatory context.

- This is not legal advice. Scope determination, lawful basis assessment, whether a breach
  is notifiable, whether a transfer mechanism is adequate, and whether you are a controller
  or a processor are legal questions. They depend on your jurisdiction, your contracts, and
  facts this skill cannot see. Get qualified counsel.
- It cannot make you certifiable. ISO/IEC 27001 certification and a SOC 2 report come from an
  accredited certification body and a licensed CPA firm respectively. PCI DSS validation
  comes from a QSA or a self-assessment questionnaire your acquirer accepts. No Markdown file
  substitutes for any of them.
- Article and section numbers here were fetched from primary sources on 2026-07-28 and are
  listed in `references/`. Law changes, guidance changes, and the same article means
  different things under different supervisory authorities. Re-check before quoting.
- It reads code. It cannot confirm that a retention job is scheduled in production, that a
  backup lifecycle rule is applied, that a processor honoured a deletion instruction, or that
  a KMS key was really destroyed. Every one of those needs runtime verification.
- No coverage of employment law, records retention duties that conflict with erasure (tax,
  accounting, medical), or sector regulation outside PCI DSS and HIPAA. Those conflicts are
  real and are discussed in [troubleshooting.md](troubleshooting.md), but the resolution is
  legal, not technical.
- Masking implementation lives in `core/logging-audit`. This skill states the obligation and
  the consequence; it does not duplicate the redaction code.
- No DPIA template, no ROPA template, no policy documents. Those are deliverables for a
  privacy function, not code.

## Security Notes

This skill contains deliberately non-compliant and insecure code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

All personal data in the examples is fabricated placeholder data. There are no real
credentials, hostnames, email addresses, card numbers, or patient records anywhere in this
skill. Keep it that way — a compliance skill that leaks a sample of real PII into a git
history is its own finding.

## References

- GDPR full text — <https://gdpr-info.eu/>
- PCI SSC Document Library — <https://www.pcisecuritystandards.org/document_library/>
- HIPAA Security Rule, 45 CFR § 164.312 — <https://www.ecfr.gov/current/title-45/section-164.312>
- NIST Privacy Framework — <https://www.nist.gov/privacy-framework>
- AICPA SOC for Service Organizations — <https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2>
- California AG CCPA FAQ — <https://oag.ca.gov/privacy/ccpa>
- CWE list — <https://cwe.mitre.org/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
