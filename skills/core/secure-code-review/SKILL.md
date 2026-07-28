---
name: secure-code-review
description: 'Review existing code for security as a repeatable process: scope the diff, map trust boundaries, hunt by sink, assign a CWE, disprove the finding before reporting it. Triggers: "code review", "security review", "audit this code", "CWE", "is this exploitable", "đánh giá mã nguồn", "lỗ hổng bảo mật".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Secure Code Review

Review code for security in a fixed order, so two reviews of the same diff produce the same
findings. The output is a list where every entry has a location, a sink, a CWE, an
exploitation path, and a fix — or it is labelled a smell and kept out of the findings list.

## When to Use

- Reviewing a diff, a PR, or a file before merge
- Auditing an unfamiliar codebase for a specific weakness class
- Checking AI-generated code before accepting it
- Deciding whether something a scanner flagged is real
- Assigning severity to a finding someone else reported

Use `core/owasp` when writing new code. Use this skill when the code already exists.

## Workflow

Five steps, in order. Skipping step 4 is what produces review reports nobody trusts.

### 1. Scope

Get the boundary of the review before reading anything.

```bash
git diff --stat origin/main...HEAD
git diff origin/main...HEAD -- '*.py' '*.ts' '*.java'
```

Three questions, answered in writing:

- What is in scope? A diff, a directory, or a weakness class across the repo.
- What is the deployment context? Internet-facing, internal, or a CLI. This changes severity
  more than any code detail.
- What is out of scope? Say it. "I did not review the Terraform" is a finding in itself if
  the diff touches it.

A diff review is not a codebase review. If a diff calls `get_document(doc_id)`, you must open
that function even though it is not in the diff. Trace one level out from every changed line.

### 2. Map trust boundaries

Build the map before hunting. You are looking for the places where data changes owner.

| Boundary | What to write down |
|---|---|
| Request entry | Every route, handler, consumer, cron, and webhook the diff touches |
| Authentication | Where the actor identity is established, and from what |
| Authorization | Where the decision is made — route, service, or query |
| Trust downgrade | Where internal code treats external data as trusted |
| Egress | Outbound HTTP, DB writes, file writes, shell, logs |

The useful output is a list of pairs: source → sink. Anything with no path from an untrusted
source to a sink is not a vulnerability, however ugly it looks.

See [references/review-process.md](references/review-process.md) for the longer version and
its mapping to the OWASP Code Review Guide.

### 3. Hunt by sink

Search for sinks, then walk backwards to the source. Sink-first beats source-first because
sinks are a short, greppable list and sources are everything.

| Sink | Grep for | CWE | Top 10 2025 |
|---|---|---|---|
| SQL string | `execute(`, `raw(`, f-string with `SELECT`, `+ " WHERE"` | CWE-89 | A05 |
| Dynamic identifier | `ORDER BY {`, `table_name`, `sort` | CWE-89 | A05 |
| HTML render | `innerHTML`, `dangerouslySetInnerHTML`, `\|safe`, `Html.Raw`, `v-html` | CWE-79 | A05 |
| Template engine | `render_template_string`, `Template(`, `compile(` | CWE-1336 | A05 |
| OS command | `shell=True`, `exec(`, `system(`, `child_process` | CWE-78 | A05 |
| Code eval | `eval(`, `new Function`, `pickle.loads` | CWE-94 | A05 |
| Deserializer | `pickle`, `yaml.load`, `ObjectInputStream`, `unserialize` | CWE-502 | A08 |
| File path | `os.path.join`, `Path(`, `readFile`, `send_file` | CWE-22 | A01 |
| Archive extract | `extractall`, `ZipFile`, `tar -x` | CWE-22 | A08 |
| Outbound HTTP | `requests.get(`, `fetch(`, `HttpClient`, `curl` | CWE-918 | A06 |
| XML parse | `etree`, `DocumentBuilder`, `SAXParser` | CWE-611 | A05 |
| Object lookup | `findUnique`, `.get(id)`, `findById` | CWE-639 | A01 |
| Missing policy | handler with no auth decorator or guard | CWE-862 | A01 |
| Wrong policy | `role ==`, `\|\|` in a permission check, tenant from body | CWE-863 | A01 |
| Token verify | `jwt.verify`, `decode(`, `verify_signature` | CWE-347 | A07 |
| Redirect | `redirect(`, `Location:`, `next=` | CWE-601 | A01 |
| Response body | `return user`, `.toJSON()`, `select *` | CWE-200 | A01 |
| Unbounded work | user-controlled `limit`, `range(`, regex on free text | CWE-770, CWE-1333 | A06 |
| Log write | `logger.info(` with request data | CWE-117 | A09 |
| Password hash | `sha256`, `md5`, `hashlib` near `password` | CWE-916 | A04 |
| Secret compare | `==` near `token`, `hmac`, `signature` | CWE-208 | A04 |
| Error handler | bare `except`, `catch (Exception`, `return true` in a catch | CWE-636, CWE-390 | A10 |

Ten of these appear in the 2025 CWE Top 25. See
[references/cwe-top25.md](references/cwe-top25.md) for the ranked list and how to pick the
right CWE rather than the closest one.

### 4. Verify adversarially

For each candidate, spend one round trying to prove it is not a finding. Five questions:

1. Can the source actually be attacker-controlled? Read the caller. Not "user input reaches
   this" but "this specific parameter, from this specific route".
2. Is there a control in between? A framework default, a middleware, a validator, a DB
   column type. Check the version and the config, not the reputation.
3. Does the sink do what you think? `execute` on some drivers takes a parameter tuple.
   `innerText` is not `innerHTML`.
4. What precondition does exploitation need? If it needs admin plus a race plus a specific
   DB engine, that is not critical.
5. Can you write the request? If you cannot state a concrete input that triggers it, you
   have a smell, not a vulnerability.

A candidate that survives all five is a finding. One that does not goes to a separate
"observations" list, or gets dropped. Do not pad the findings list — see
[common-mistakes.md](common-mistakes.md#reporting-a-smell-as-a-vulnerability).

### 5. Report

One block per finding:

```text
Title        Short, names the weakness and the location
Location     file:line, plus the sink and the source route
CWE          The specific one, with the name
Top 10       A0x:2025, and API-x:2023 if it is an API
ASVS         Chapter (V1 to V17)
Exploit      A concrete request or input that triggers it
Impact       What the attacker gets, and for how many users
Severity     With reasoning, not just a label
Fix          The minimal change, and a regression test that fails before it
```

Observations go under a separate heading with one line each. Naming them keeps them out of
the findings count while still telling the author what you saw.

## Severity

Severity is exploitability multiplied by blast radius. Assign it from those two, then
sanity-check against a CVSS vector if you need to talk to people outside the review.

| | Blast radius: all users / RCE | One tenant | Single account | Self only |
|---|---|---|---|---|
| **Unauthenticated, remote** | Critical | High | High | Medium |
| **Any authenticated user** | Critical | High | Medium | Low |
| **Same-tenant privileged** | High | Medium | Medium | Low |
| **Admin only** | Medium | Medium | Low | Low |
| **Needs local access or a race** | Medium | Low | Low | Informational |

Rules that keep this honest:

- Category does not set severity. SQL injection on an admin-only endpoint behind a
  server-side integer cast is not critical.
- Chained findings are rated as the chain, once, not as three separate mediums.
- Defence-in-depth gaps with no path are Informational. Not Low.
- Internet-facing beats internal. Say which you assumed.

CVSS v4.0 is a communication tool for people who need a number. It is not a triage
mechanism: it has no idea whether the affected table holds session tokens or feature flags.
Publish the vector, label it `CVSS-B` if you only scored Base metrics, and keep your own
severity alongside it. See [references/cvss-4.0.md](references/cvss-4.0.md).

## Reviewing AI-Generated Code

The failure modes differ from human code. Human code fails from haste; generated code fails
from plausibility. It compiles, reads well, names things correctly, and puts the control in
the wrong place.

Four patterns to check first:

1. Auth check in the wrong layer. A `useEffect` that redirects unauthenticated users, with no
   server-side check behind it. Looks like authorization, runs on the client.
2. Validation without encoding. A Zod or Pydantic schema at the boundary, then raw
   interpolation at the sink. The schema makes the diff look safe.
3. Fail-open error handling. `try/catch` around a permission call returning the permissive
   default, usually with a comment saying it is for resilience.
4. Invented API surface. A call to a config option or library method that does not exist in
   the pinned version, so the control silently does nothing. Check it against the lockfile.

See [best-practices.md](best-practices.md#reviewing-ai-generated-code) for the full list with
code.

## Related Skills

- `core/owasp` — the standards themselves, and controls for new code
- `core/api-security` — API-specific weakness classes
- `core/authentication` — auth and session review depth
- `core/devsecops` — wiring SAST and secret scanning into CI so this review is not the only gate

## Supporting Files

- [README.md](README.md) — purpose, layout, standards, limitations
- [checklist.md](checklist.md) — pre-return verification for the review itself
- [best-practices.md](best-practices.md) — review patterns and secure refactoring
- [common-mistakes.md](common-mistakes.md) — how reviews go wrong
- [troubleshooting.md](troubleshooting.md) — when a finding cannot be resolved
- [prompts.md](prompts.md) — prompts that produce findings, and anti-patterns
- [references/](references/) — CWE Top 25, review process, ASVS, CVSS, Top 10
- [examples/](examples/) — eight findings, two of which are not vulnerabilities
