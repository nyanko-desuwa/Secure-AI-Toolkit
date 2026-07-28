# OWASP Top 10 2025 — for review reporting

Current released version. Verified against <https://owasp.org/Top10/2025/> on 2026-07-28.

This file is the reporting view: given a sink you found, which category do you write on the
finding. For the design view — what each category implies when writing new code — see
`skills/core/owasp/references/owasp-top10-2025.md`.

## What the category is for

The Top 10 category is the line on the finding that a non-specialist reads. It buys you
prioritisation and a shared vocabulary. It does not buy you precision: A01 covers IDOR, path
traversal, CORS trust, and SSRF, which have nothing in common at the code level.

So write both. The category is for the reader, the CWE is for the fix. A finding with only a
category is vague; a finding with only a CWE does not survive contact with a steering meeting.

## Categories, and the sinks that land in each

| Category | Sinks and shapes you will actually find |
|---|---|
| A01 Broken Access Control | Object lookup with no actor predicate, handler with no policy, role read from request body, path traversal, over-broad response body, open redirect, SSRF (no standalone slot) |
| A02 Security Misconfiguration | Debug flag, permissive CORS, missing security headers, cookie without `HttpOnly`/`Secure`/`SameSite`, stack trace in a response, default credentials |
| A03 Software Supply Chain Failures | Unpinned version, missing lockfile, install script from a fresh package, CI step pulling a mutable tag, typosquat-shaped name |
| A04 Cryptographic Failures | Fast hash on a password, `random` for a token, ECB or a static IV, hardcoded key, TLS verification disabled, `==` on a secret |
| A05 Injection | SQL string, dynamic identifier, `shell=True`, `eval`, template compiled from input, `innerHTML`, XXE-capable parser |
| A06 Insecure Design | Missing rate limit on an expensive flow, no bound on a user-supplied `limit`, workflow that can be replayed out of order, trust in a client-computed price |
| A07 Authentication Failures | `jwt.verify` without `algorithms`, session not rotated on privilege change, session alive after logout, guessable reset token, user enumeration through differing errors |
| A08 Software or Data Integrity Failures | `pickle.loads`, `yaml.load`, `ObjectInputStream`, `unserialize`, upload trusting `Content-Type`, `extractall` on an untrusted archive, unverified update artefact |
| A09 Security Logging and Alerting Failures | No log on an authorization denial, secret in a log line, unescaped newline from user input in a log, audit trail the user can delete |
| A10 Mishandling of Exceptional Conditions | `catch` returning the permissive default, bare `except: pass` around a security call, partial write with no rollback, error message carrying internal state |

## Two things about the 2025 edition that break old findings

A03 and A10 are new. Injection moved from A03 to A05. So `A03` on a report means "vulnerable
components" in a 2021 report and "supply chain" in a 2025 report, and an `A03: SQL injection`
finding is now wrong rather than merely dated. When you inherit a finding list, check which
edition it was written against before renumbering.

SSRF lost its standalone slot (it was A10:2021). It did not become less common. Report it under
A01 or A06 with `CWE-918`, which is rank 22 on the 2025 CWE Top 25 — the CWE carries the weight
the category no longer does.

## Mapping from 2021

| 2021 | 2025 |
|---|---|
| A01 Broken Access Control | A01 Broken Access Control |
| A02 Cryptographic Failures | A04 Cryptographic Failures |
| A03 Injection | A05 Injection |
| A04 Insecure Design | A06 Insecure Design |
| A05 Security Misconfiguration | A02 Security Misconfiguration |
| A06 Vulnerable and Outdated Components | A03 Software Supply Chain Failures (broadened) |
| A07 Identification and Authentication Failures | A07 Authentication Failures |
| A08 Software and Data Integrity Failures | A08 Software or Data Integrity Failures |
| A09 Security Logging and Monitoring Failures | A09 Security Logging and Alerting Failures |
| A10 Server-Side Request Forgery | folded into A01 / A06, no standalone category |

A10:2025 has no 2021 predecessor.

## API surfaces get a second category

If the reviewed code is a REST, GraphQL, or gRPC handler, add the API Security Top 10 2023
category. It is more specific than the general Top 10 for the failures that dominate APIs:

| Finding | Top 10 2025 | API Top 10 2023 |
|---|---|---|
| Object readable by a non-owner | A01 | API1 Broken Object Level Authorization |
| Endpoint returns fields the caller may not see | A01 | API3 Broken Object Property Level Authorization |
| Admin function reachable by a normal user | A01 | API5 Broken Function Level Authorization |
| No bound on page size or request rate | A06 | API4 Unrestricted Resource Consumption |
| Server fetches a user-supplied URL | A01 / A06 | API7 Server Side Request Forgery |
| Upstream API response trusted without validation | A08 | API10 Unsafe Consumption of APIs |

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
