---
name: deserialization-security
description: 'Unsafe deserialization and parsers - pickle, Java/.NET binary, YAML load, XML XXE/expansion. Triggers: "deserialization", "pickle", "ObjectInputStream", "BinaryFormatter", "YAML load", "XXE", "unserialize", "giải tuần tự hóa", "XML external entity".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Deserialization Security

Data is not harmless because it looks structured. A format that can choose a class, construct an
object graph, resolve an external entity, or expand recursively can cross from input to code or
resource exhaustion. This skill owns unsafe binary deserialization and parser settings.

## When to Use

- Code uses `pickle`, `ObjectInputStream`, `BinaryFormatter`, `unserialize`, YAML loaders, or XML parsers
- Import jobs accept structured documents or serialized state
- Reviewing type metadata, polymorphic JSON, parser defaults, or entity resolution

## When NOT to Use

| Concern | Route to |
|---|---|
| JSON API schemas and endpoint authz | `api-security` |
| File acceptance/storage/serving pipeline | `file-upload-security` |
| Framework request/model binding | `mvc-security` |

## The Standard

| Failure | Mapping |
|---|---|
| Untrusted object deserialization | CWE-502 · A08 |
| XML external entity / entity expansion | CWE-611/CWE-776 · A05/A06 |
| Unsafe YAML type construction | CWE-502 · A08 |
| Uncontrolled polymorphic type | CWE-502 · A08 |

OWASP Top 10 2025 A08, ASVS 5.0 V2/V5/V13, and CWE are the sources; see [references/](references/).

## Workflow

1. Inventory every decode/parser call and its source: request, queue, cache, file, database, or peer.
2. Identify whether the format can select types, invoke constructors, resolve external resources, or
   grow unboundedly.
3. Replace unsafe formats with data-only formats where possible. Otherwise use a maintained safe
   parser, strict allowlist, size/depth/time limits, and an isolation boundary.
4. Run [checklist.md](checklist.md). Report file:line, input origin, reachable dangerous behavior,
   CWE, fix, and preconditions.

## Severity

- Critical - untrusted bytes can instantiate arbitrary types or execute privileged behavior
- High - external entity reads or unbounded expansion reaches sensitive files/network/resources
- Medium - unsafe parser on authenticated but low-trust import data
- Low - deprecated API unreachable from untrusted input, with migration planned

## Related Skills

`api-security` · `file-upload-security` · `mvc-security` · `secure-code-review`

## Supporting Files

[README.md](README.md) · [checklist.md](checklist.md) · [best-practices.md](best-practices.md) ·
[common-mistakes.md](common-mistakes.md) · [troubleshooting.md](troubleshooting.md) ·
[prompts.md](prompts.md) · [references/](references/) · [examples/README.md](examples/README.md)
