---
name: common-pitfalls
description: 'Find the mistakes that AI-generated code ships by default: secrets in the browser bundle, security decisions made in the client, missing limits, leaks, and cost traps. Triggers: "hardcoded", "API key in frontend", "NEXT_PUBLIC", "memory leak", "app is slow", "bill jumped", "lộ key", "rò rỉ bộ nhớ".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Common Pitfalls

This skill is for code that was described in words and written by an AI. That code usually
works. What it does not do is survive contact with a stranger, a large table, or a monthly
bill.

The assumption here is that nobody will read the code closely enough to catch the mistake.
So each fix has to remove the unsafe option, not ask for discipline.

## When to Use

- Before shipping anything an AI wrote for you
- After a bill went up and you do not know why
- When the app works on your machine and fails in production
- When memory or response times climb the longer the app runs
- When you think a key may have leaked
- Before adding a login, a payment, or an admin screen

## The Seven Families

| Family | What it costs | Primary category |
|---|---|---|
| 1. Secrets shipped to the browser | Someone else spends your credits, reads your data | A04:2025 · CWE-798, CWE-540 |
| 2. Hardcoded values that should be config | Works locally, breaks or corrupts data in production | A02:2025 · CWE-1188 |
| 3. Hardcoded or missing limits | Truncated results, or one request that takes the app down | A06:2025 · API4:2023 · CWE-770 |
| 4. Security decided in the client | Any visitor becomes an admin | A01:2025 · CWE-602, CWE-807 |
| 5. Memory and resource leaks | Restarts, then downtime under load | A10:2025 · CWE-401, CWE-772 |
| 6. Performance traps | Slower every week, then an outage or a bill | A10:2025 · CWE-400 |
| 7. Swallowed errors and data loss | A failure looks like success until the data is gone | A10:2025 · CWE-390 |

Full mapping, including ASVS chapters, is in
[references/owasp-mapping.md](references/owasp-mapping.md).

## Workflow

Work in this order. It is ordered by how much damage the finding does before anyone notices,
not by how hard it is to fix.

### 1. Search the build output for secrets

Not the source. The build. A key can be absent from every file you wrote and still be sitting
in the JavaScript your visitors download.

```bash
npm run build
grep -rEn "sk-ant-|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|service_role|-----BEGIN" dist/ build/ .next/static/ 2>/dev/null
```

Then grep for the literal value of each secret you know about. Commands and per-stack details
are in [references/secret-exposure.md](references/secret-exposure.md).

Any hit means that key is burned. Rotate it. Deleting the line does not un-leak it.

### 2. Find every security decision and ask where it runs

Search for role checks, admin flags, and route guards. For each one, answer: if someone sends
the request directly with `curl`, ignoring your UI entirely, what stops them?

If the answer is "the button is hidden", there is no control. Hiding a button is a UX choice.

### 3. Find what has no limit

Every list endpoint, every upload, every outbound HTTP call, every retry loop, every cache,
every loop over user input. Each needs a maximum. Missing limits are a security finding -
`API4:2023 Unrestricted Resource Consumption`, `CWE-770` - not a performance nitpick.

Starting values worth copying are in
[references/resource-limits.md](references/resource-limits.md).

### 4. Find what is never released

Listeners added per request, `setInterval` never cleared, module-level `Map` used as a cache,
`useEffect` with no cleanup, database connections opened and not closed. See
[best-practices.md](best-practices.md#5-memory-and-resource-leaks).

### 5. Find the loops that cost money

`await` inside a `for` loop over database rows. An LLM or metered API called once per item. A
polling interval with no ceiling. These are invisible at ten records and fatal at ten thousand.

### 6. Find the errors that go nowhere

`catch {}`, `except: pass`, a promise with no `.catch`, a write whose result is never checked.
A silent failure is worse than a crash, because you find out weeks later.

### 7. Verify and report

Run [checklist.md](checklist.md). For each finding, say the cost in plain words before the
technical explanation: what an attacker or a busy Tuesday actually gets.

## Severity

Rank by what it costs before anyone notices.

- Critical - a live secret in a public bundle or public repo, or any visitor can read or
  change other people's data. Money leaves, or data leaves, today.
- High - an authenticated user can reach data or actions that are not theirs. One request can
  exhaust the process. A write can be lost silently.
- Medium - degrades under growth or load: no pagination on a table that will get big, a leak
  that needs a weekly restart, a hardcoded limit that truncates results.
- Low - hardcoded value with no security or correctness impact, a magic number, a missing
  timeout on a call to something you control.

Do not inflate. A hardcoded `localhost` in a script that only ever runs locally is low. A
hardcoded `localhost` in a database URL that got deployed is critical, because production may
be reading nothing or writing to the wrong place.

## Related Skills

- `secrets-management` - where secrets should live, rotation, and leaked-secret response
- `frontend-security` - XSS, CSP, token storage in the browser
- `owasp-security` - the standards these findings map to
- `api-security` - object-level authorization and rate limiting in depth
- `database-security` - RLS, query safety, index and connection concerns
- `logging-audit` - what to log when you stop swallowing errors
- `publish-safety` - the same leaks at the moment they become public: push, package, image, bundle

## Supporting Files

- [README.md](README.md) - purpose, who it is for, limitations
- [checklist.md](checklist.md) - pre-ship checks, grouped by family
- [best-practices.md](best-practices.md) - the safe default per family
- [common-mistakes.md](common-mistakes.md) - the catalogue: shape, cost, fix
- [troubleshooting.md](troubleshooting.md) - start from the symptom
- [prompts.md](prompts.md) - prompts that produce a real audit
- [references/secret-exposure.md](references/secret-exposure.md) - where secrets leak, per stack
- [references/resource-limits.md](references/resource-limits.md) - limits worth starting from
- [references/owasp-mapping.md](references/owasp-mapping.md) - family to standard
- [examples/README.md](examples/README.md) - twelve vulnerable/fixed pairs
