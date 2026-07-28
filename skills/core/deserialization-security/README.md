# Deserialization Security Skill

## Purpose

Unsafe deserialization is a boundary failure: the program accepts a representation that has behavior
instead of data. Pickle, Java serialization, .NET BinaryFormatter, unsafe YAML, XML external
entities, and PHP serialization need a different response than ordinary JSON validation.

## How It Works

```text
SKILL.md                   workflow and severity
README.md                  purpose and limits
checklist.md               source, parser, type, entity, limit checks
best-practices.md          vulnerable/fixed patterns
common-mistakes.md         wrong fixes
troubleshooting.md         migration conflicts
prompts.md                 four review tiers
references/                CWE and parser source pins
examples/README.md         seven vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 A08/A05/A06 | 2026-07-28, <https://owasp.org/Top10/2025/> |
| OWASP ASVS | 5.0.0 V2/V5/V13 | 2026-07-28 |
| CWE | CWE-502, CWE-611, CWE-776 | 2026-07-28, <https://cwe.mitre.org/> |

## Configuration

None. This is read-only guidance.

## Example Usage

```text
Find every parser and deserializer in src and workers. For each, identify input source, whether it
can construct types or resolve entities, configured limits, and the data-only replacement. Report
file:line, CWE, exploit precondition, fix, and tests needed.
```

## Limitations

- A code review cannot prove every gadget or library behavior; do not use that uncertainty to call
  an unsafe deserializer safe.
- Safe parser configuration depends on language/library version; verify vendor documentation.
- This skill intentionally does not provide exploit gadget chains or payloads.
- File storage, malware scanning, and endpoint authorization remain separate skills.

## Security Notes

Vulnerable blocks show unsafe APIs only and are paired with safe patterns. No runnable exploit
payloads, real hosts, credentials, or gadget chains are included.
