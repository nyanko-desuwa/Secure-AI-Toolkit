# Logging and Audit Skill

Guidance for logging as a security control and logging as a security risk. Both halves are in
scope, because the same file is the only evidence you will have after an incident and a
plausible place to find a plaintext password.

## Purpose

Give an AI assistant a defensible answer to four questions:

- What events must this code emit, and with which fields?
- What must never reach the log pipeline, and where is that enforced?
- Is this an application log or an audit trail, and does the storage match?
- What alerts on it, and has that rule ever fired?

Every control traces to `A09:2025 Security Logging and Alerting Failures`, an ASVS 5.0 V16
requirement, or a CWE. An uncited control is an opinion.

## How It Works

Plain Markdown. Nothing executes. The assistant reads `SKILL.md`, follows the six-step
workflow (inventory, name the event, emit safely, separate the audit trail, close the loop
with an alert, verify), and pulls in the file it needs at each step.

```text
SKILL.md                        entry point: workflow, severity, related skills
README.md                       this file
checklist.md                    pre-return verification, grouped
best-practices.md               patterns with vulnerable/fixed pairs
common-mistakes.md              what goes wrong and why the fix works
troubleshooting.md              when the guidance cannot be applied
prompts.md                      prompts that produce findings, plus anti-patterns
references/
  owasp-a09-2025.md             the category, its five CWEs, its own conditions list
  asvs-v16-logging.md           V16 requirement table, levels, citation practice
  detection-rules.md            event vocabulary and the rules worth having
examples/
  README.md                     eight vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025, A09 Security Logging and Alerting Failures | 2026-07-28, against `owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30), V16 | 2026-07-28, against the ASVS 5.0 source file on GitHub |
| OWASP Logging Cheat Sheet | current | 2026-07-28, against `cheatsheetseries.owasp.org` |
| OWASP Application Logging Vocabulary Cheat Sheet | current | 2026-07-28, against `cheatsheetseries.owasp.org` |
| CWE | CWE-117, CWE-221, CWE-223, CWE-532, CWE-778 | 2026-07-28, as mapped by A09:2025 |

V16 requirement numbers in `references/asvs-v16-logging.md` were read from the 5.0.0 source,
not recalled. ASVS 5.0 renumbered everything from 4.0.3, so a `V7.x` logging ID from an older
report does not map.

## Configuration

None. No build step, no dependency, no environment variable.

To use the skill in Claude Code, keep this repository in the working directory so
`skills/core/logging-audit/SKILL.md` is readable, or copy the `logging-audit` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search, and web
lookup plus `ls`/`cat`; it cannot run arbitrary commands.

## Example Usage

Find the missing events rather than reviewing the ones that exist:

```text
Read src/api/ and list every authorization denial path. For each, say whether it emits a
log event. Report only the ones that do not.
```

Check the leak direction:

```text
Search this repo for log calls that pass a whole request, response, user, or exception
object. For each, name the sensitive field that would reach the log and the CWE.
```

Wire an alert to its emitter:

```text
Here are our five detection rules. For each, find the code path that emits the event it
keys on. If nothing emits it, say so - that rule has never fired.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a scanner. It cannot follow a value from a request body through
  three call frames into a log statement. Pair it with SAST rules for log sinks and a secret
  scanner pointed at the log store itself.
- Reading code cannot confirm runtime behaviour. Whether the redaction processor is actually
  registered, whether the sink is append-only, whether the alert reaches a human - none of
  that is visible in a diff. Every claim about deployed state needs a runtime check.
- Detection rules in `references/detection-rules.md` are pseudo-queries. SIEM syntax differs
  per product; translation is on you, and thresholds must be tuned against your baseline or
  they page nightly and get muted.
- No product configuration. Nothing here covers Splunk, Sentinel, Elastic, Datadog, or
  CloudWatch setup, index lifecycle policy, or agent deployment.
- Alerting and correlation are explicitly out of ASVS scope. ASVS gets you the events; the
  alerting obligation comes from A09. Do not read an ASVS V16 pass as coverage of alerting.
- Compliance mapping is partial. GDPR Articles 15 and 17 are named where they collide with
  append-only audit trails. PCI DSS, HIPAA, SOC 2, and ISO 27001 retention requirements are
  not covered - those belong in a `compliance` skill.
- Tamper evidence has a hard ceiling. Hash chaining detects deletion by an attacker without
  full table write access. It proves nothing against one who has it. External anchoring is
  named in `best-practices.md` but not implemented here.
- Examples are Python (structlog), TypeScript (pino), Java (Logback), Go (`slog`), and SQL.
  The patterns generalise; the syntax does not.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

The log injection payloads in `examples/README.md` and `best-practices.md` are real working
payloads, kept intentionally so a reader recognises one in their own log store. They forge log
entries; they do not execute code.

All values are placeholders. No real credentials, hostnames, IP addresses, or personal data
appear anywhere in this skill. Example domains use `.test` or `example.com`.

## References

- OWASP Top 10 2025 A09 - <https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
- OWASP ASVS 5.0 V16 - <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>
- OWASP Logging Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- OWASP Application Logging Vocabulary Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html>
- CWE-117 Improper Output Neutralization for Logs - <https://cwe.mitre.org/data/definitions/117.html>
- CWE-532 Insertion of Sensitive Information into Log File - <https://cwe.mitre.org/data/definitions/532.html>
- CWE-778 Insufficient Logging - <https://cwe.mitre.org/data/definitions/778.html>
