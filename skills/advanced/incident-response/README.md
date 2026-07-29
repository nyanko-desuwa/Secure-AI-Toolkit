# Incident Response Skill

Guidance for handling a security incident in a software system: what to capture, what to
revoke, what to say, and in which order.

## Purpose

Under pressure, teams reach for the action that makes the alert stop. That action is usually
a reboot, a reimage, or a `terminate-instances`, and it destroys the evidence needed to
answer the only question that matters: what else did they reach? This skill front-loads the
decisions so the first hour does not cost you the second.

Every control names its NIST SP 800-61r3 subcategory, and a CWE where the underlying weakness
has one. An uncited control is an opinion.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the seven-step
workflow, and pulls the supporting file it needs per step.

```text
SKILL.md                          workflow, severity, entry point
README.md                         this file
checklist.md                      per-phase verification
best-practices.md                 patterns with wrong/right pairs
common-mistakes.md                what goes wrong under pressure
troubleshooting.md                when the guidance cannot be applied
prompts.md                        prompt examples per task
references/
  nist-800-61.md                  r3 structure, subcategory IDs, verified quotes
  severity-classification.md      SEV matrix with worked examples
  runbook-template.md             fillable runbook, generic across incident types
examples/
  README.md                       eight incidents, wrong response next to right
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| NIST SP 800-61 | Revision 3, April 2025 | 2026-07-28, against the PDF at the DOI |
| NIST CSF | 2.0 (CSWP 29, February 2024) | 2026-07-28, csrc.nist.gov |
| NIST SP 800-86 | August 2006, still final | 2026-07-28, csrc.nist.gov |
| NIST SP 800-184 | December 2016, still final | 2026-07-28, csrc.nist.gov |
| RFC 3227 / BCP 55 | February 2002 | 2026-07-28, rfc-editor.org |
| MITRE ATT&CK Enterprise | v19.1 (v19.0 released 2026-04-28) | 2026-07-28, attack.mitre.org |
| OWASP Top 10 for LLM Applications | 2025 | 2026-07-28, genai.owasp.org |
| OWASP Top 10 | 2025 | pinned by the toolkit |

Versions are pinned in `references/` with the date checked. ATT&CK ships several releases a
year; re-check technique IDs before quoting them in a report.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/advanced/incident-response/SKILL.md` is readable, or copy the `incident-response`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read,
search, and web lookup plus `ls`/`cat` - it cannot run containment commands on your behalf,
which is deliberate.

## Example Usage

Triage a fresh report:

```text
A contractor's GitHub PAT was found in a public gist. It had repo and workflow scope on our
org. Walk me through the first hour using skills/advanced/incident-response. Give me a
severity with reasoning, what to preserve before revoking, and the log queries that scope it.
```

Review a runbook before you need it:

```text
Read ops/runbooks/database-breach.md and check it against
skills/advanced/incident-response/checklist.md. Tell me which steps destroy evidence and
which NIST SP 800-61r3 subcategory each gap maps to.
```

More in [prompts.md](prompts.md).

## Limitations

- Not a forensics course. Real disk and memory forensics needs trained examiners and tooling;
  this skill covers capture and handoff, and says where the line is. See SP 800-86.
- No legal or notification deadlines. Breach notification is jurisdictional and changes
  often - r3 says so itself. Deadlines belong to `compliance` and your legal team.
- Commands are illustrative, in Bash, Python, and cloud CLIs. Yours will differ by platform,
  and a command that works on Linux will not work on a managed database.
- No attribution guidance. Naming a threat actor from log evidence is beyond what a
  development team can defensibly do, and a wrong attribution shapes the whole response.
- No malware analysis. Do not run a captured sample to see what it does.
- Cannot tell you whether your detection actually fired. Reading code and configuration does
  not confirm runtime behaviour; verify in the log pipeline.
- ATT&CK technique IDs are cited at technique level, not sub-technique, unless the
  sub-technique was verified directly.

## Security Notes

This skill contains deliberately wrong response procedures in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Wrong:` or `Vulnerable:`
and paired with a corrected version. Do not lift a labelled-wrong block into a runbook.

Everything here is defensive and assumes you are responding on systems you own or are
authorized to defend. There is no offensive tooling, no guidance on attacking a third party,
and nothing about "counter-hacking" - which is illegal in most jurisdictions regardless of
who started it. Ransom payment decisions are a business and legal matter, not an engineering
one; this skill does not advise on them.

All hostnames, keys, account IDs, and identifiers are placeholders. `ghp_EXAMPLE`,
`123456789012`, and `example.com` are not real.

## References

- NIST SP 800-61r3 - <https://doi.org/10.6028/NIST.SP.800-61r3>
- NIST CSF 2.0 - <https://doi.org/10.6028/NIST.CSWP.29>
- NIST SP 800-86 - <https://csrc.nist.gov/pubs/sp/800/86/final>
- NIST SP 800-184 - <https://csrc.nist.gov/pubs/sp/800/184/final>
- RFC 3227 - <https://www.rfc-editor.org/rfc/rfc3227.html>
- MITRE ATT&CK - <https://attack.mitre.org/>
- OWASP Top 10 for LLM Applications 2025 - <https://genai.owasp.org/llm-top-10/>
- CISA Incident & Vulnerability Response Playbooks - <https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks>
