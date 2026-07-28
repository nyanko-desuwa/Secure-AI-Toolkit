# Secure Architecture Skill

Design-level security. The findings here are the ones that survive a clean code review because
nothing in any single file is wrong.

## Purpose

Give an assistant a repeatable way to answer four questions about a system design: where are the
trust boundaries, what crosses them, what enforces the crossing, and what happens when the
enforcement is unavailable. Every control names its standard so a design decision can be defended
in review rather than asserted.

The distinguishing test for scope: if fixing the problem in one file leaves the same problem
reachable by a second path, it belongs here. If it is contained in one function, it belongs in
`core/owasp`.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the six-step workflow
(boundaries, threat model, control placement, failure modes, ADR, verify), and pulls the
supporting file it needs at each step.

```text
SKILL.md                          workflow, severity, scope tests
README.md                         this file
checklist.md                      pre-return verification, grouped by boundary
best-practices.md                 patterns, each with a vulnerable/fixed pair
common-mistakes.md                what goes wrong and why the fix works
troubleshooting.md                when the secure design is not available
prompts.md                        prompts that produce findings, anti-patterns
references/
  owasp-architecture.md           A01, A02, A06 and ASVS V8, V13, V15 at design level
  nist-zero-trust-800-207.md      the seven tenets, quoted and dated
  threat-modeling.md              STRIDE, LINDDUN, the Manifesto's four questions
  nist-ssdf-800-218.md            PO/PS/PW/RV practice groups
  cwe-architecture.md             the design-level CWEs used in this skill
examples/
  README.md                       seven vulnerable/fixed architecture pairs
  tenant-isolation.sql            row-level security, before and after
  service-authz.yaml              Kubernetes NetworkPolicy and mTLS peer auth
  iam-least-privilege.tf          wildcard IAM policy versus scoped policy
  secure-defaults.yaml            deny-by-default application configuration
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 (A01, A02, A06, A08) | 2026-07-28, `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0, released 2025-05-30 (V8, V13, V15) | 2026-07-28, ASVS project page |
| NIST SP 800-207 Zero Trust Architecture | August 2020 | 2026-07-28, read from the published PDF |
| NIST SP 800-218 SSDF | 1.1, February 2022 | 2026-07-28, `csrc.nist.gov` |
| OWASP Threat Modeling Cheat Sheet | undated, live page | 2026-07-28, `cheatsheetseries.owasp.org` |
| Threat Modeling Manifesto | undated, live page | 2026-07-28, `threatmodelingmanifesto.org` |
| LINDDUN | GO, PRO, MAESTRO variants | 2026-07-28, `linddun.org` |
| CWE | 250, 359, 602, 653, 668, 693, 1188, 1220 | 2026-07-28, `cwe.mitre.org` |

Version numbers and check dates live in `references/`. When a standard moves, update the
reference file and this table together.

## Configuration

None. No build step, no dependency, no environment variable.

To use in Claude Code, keep this repository in the working directory so
`skills/advanced/secure-architecture/SKILL.md` is readable, or copy the `secure-architecture`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search,
and web lookup plus `ls`/`cat`.

The example files are illustrations, not a starter kit. `iam-least-privilege.tf` and
`service-authz.yaml` reference placeholder account IDs, bucket names, and namespaces. Read them,
then write your own against your real resource names.

## Example Usage

Review a design before it is built:

```text
Here is the design for a new billing service. Identify the trust boundaries, and for each one
tell me what is authenticated, what is authorized, and what happens when the check fails.
Use skills/advanced/secure-architecture/SKILL.md.
```

Find architectural findings in existing code:

```text
Read src/ and infra/. Report only findings where fixing it in one file leaves the same problem
reachable by another path. Skip anything a linter would catch.
```

Threat model one boundary:

```text
STRIDE the crossing between our public API and the internal orders service. Assume the attacker
already has a valid low-privilege account.
```

More in [prompts.md](prompts.md).

## Limitations

- Reads designs and configuration; cannot confirm deployment. A correct `NetworkPolicy` in git is
  not a `NetworkPolicy` in the cluster. Every finding about runtime state is unverified unless
  someone checked the cluster.
- No cost or latency model. Several recommendations here — per-tenant keys, mTLS everywhere,
  break-glass workflows — cost real money and real p99. The skill states the security position
  and names the tradeoff; it cannot decide it for you.
- Cloud examples are AWS-flavoured for IAM and Kubernetes-flavoured for network policy. The
  reasoning transfers to Azure and GCP; the syntax does not.
- Zero trust coverage is architectural. NIST SP 800-207 spends most of its length on deployment
  variants, migration, and threats to ZTA itself. The seven tenets are quoted here; the migration
  guidance is not.
- ASVS mapping is chapter level (V8, V13, V15), not requirement IDs. For formal verification work
  from the official ASVS 5.0 source.
- No compliance mapping. SOC 2, ISO 27001, and GDPR Article 25 sit close to this material but are
  the `compliance` skill's job.
- Threat modelling here is manual and structured. It does not replace an adversarial review by
  someone who did not write the design. The Manifesto's Hero Threat Modeler anti-pattern cuts
  both ways: one assistant is not a varied viewpoint either.

## Security Notes

This skill contains deliberately insecure architecture and configuration in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired with
a fixed version. Do not lift a labelled-vulnerable block into a project.

All identifiers are placeholders: `123456789012` for AWS account IDs, `example.com` for hostnames,
`acme` for tenant names. No real credentials, ARNs, endpoints, or personal data appear anywhere in
this skill.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Threat Modeling Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>
- Threat Modeling Manifesto — <https://www.threatmodelingmanifesto.org/>
- LINDDUN — <https://linddun.org/>
- NIST SP 800-207 Zero Trust Architecture — <https://csrc.nist.gov/pubs/sp/800/207/final>
- NIST SP 800-218 SSDF 1.1 — <https://csrc.nist.gov/pubs/sp/800/218/final>
- CWE — <https://cwe.mitre.org/>
