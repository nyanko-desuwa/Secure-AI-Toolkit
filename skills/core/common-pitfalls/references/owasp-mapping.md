# Family to Standard

What to cite when you write up a finding. Mapping is at the level the standards support: Top 10
category, API Top 10 category, ASVS chapter, and CWE. No ASVS requirement IDs appear here,
because they were not verified against the official requirement list.

Versions used, verified 2026-07-28: OWASP Top 10 2025, OWASP API Security Top 10 2023, OWASP
ASVS 5.0.0 (released 2025-05-30).

One note that trips people up: the 2025 Top 10 is not a renumbering of 2021. A03 (Software Supply
Chain Failures) and A10 (Mishandling of Exceptional Conditions) are new, and Injection moved from
A03 to A05. A finding written against the 2021 list will cite the wrong letter.

## The seven families

| Family | Top 10 2025 | API Top 10 2023 | ASVS chapter | CWE |
|---|---|---|---|---|
| 1. Secrets shipped to the browser | A04 Cryptographic Failures | API8 Security Misconfiguration | V14 Data Protection | CWE-798, CWE-540, CWE-615 |
| 2. Hardcoded values that should be config | A02 Security Misconfiguration | API8 | V13 Configuration | CWE-1188, CWE-547 |
| 3. Hardcoded or missing limits | A06 Insecure Design | API4 Unrestricted Resource Consumption | V2 Validation, V4 API, V5 File Handling | CWE-770, CWE-400 |
| 4. Security decided in the client | A01 Broken Access Control, A07 Authentication Failures | API1, API3, API5 | V6 Authentication, V8 Authorization, V9 Self-contained Tokens | CWE-602, CWE-807, CWE-347, CWE-259 |
| 5. Memory and resource leaks | A10 Mishandling of Exceptional Conditions | API4 | V15 Secure Coding and Architecture | CWE-401, CWE-772 |
| 6. Performance and cost traps | A10 | API4, API6 | V15 | CWE-400, CWE-405 |
| 7. Swallowed errors and data loss | A09 Security Logging and Alerting Failures, A10 | API8 | V16 Secure Logging and Error Handling | CWE-390, CWE-209, CWE-703 |

## Category by category

### A01:2025 Broken Access Control

Everything in family 4 that concerns what a user is allowed to reach. A role check in the
browser, a route guard with no server counterpart, a query not scoped to the acting user, a
Supabase table with Row Level Security disabled. ASVS V8. `CWE-602` for client-side enforcement,
`CWE-807` when the decision reads untrusted input.

At the API level this splits three ways: API1 for reaching another user's object, API3 for
reading or writing a field the user should not control, API5 for reaching an admin function.

### A02:2025 Security Misconfiguration

Family 2, plus the deployment-shaped mistakes: debug mode on in production, a permissive CORS
policy, a `/test` route left reachable, verbose error pages. ASVS V13. `CWE-1188` for an insecure
default that was never changed.

### A04:2025 Cryptographic Failures

Family 1. A secret in a public bundle is a failure to protect data at rest and in transit, which
is what this category covers. ASVS V14. `CWE-798` hardcoded credentials, `CWE-540` information in
source code, `CWE-615` information in source code comments.

`CWE-295` (improper certificate validation) also lands here when `rejectUnauthorized: false` or
`verify=False` was added to silence an error, since it removes transport protection. ASVS V12
Secure Communication is the relevant chapter for that one.

### A05:2025 Injection

Not a focus of this skill. Injection is covered in depth by `owasp-security` and
`database-security`. It appears here only where a hardcoded string interpolation shows up
alongside another pitfall.

### A06:2025 Insecure Design

Family 3. A missing limit is a design gap, not an implementation slip: the design never decided
what the maximum was. ASVS V2 and V4. `CWE-770` allocation without limits.

### A07:2025 Authentication Failures

The credential half of family 4. A hardcoded password or PIN (`CWE-259`), a bypass token, a JWT
decoded without verification (`CWE-347`), an `isAdmin = true` left from testing. ASVS V6 and V9.

### A09:2025 Security Logging and Alerting Failures

Half of family 7. A swallowed error is an unlogged security event. So is a failed write nobody
was told about. If nothing alerts, the incident is discovered by a customer. ASVS V16.

### A10:2025 Mishandling of Exceptional Conditions

New in 2025, and it carries a lot of this skill. It covers resource release on the error path,
failing open, unhandled rejections, and the empty `catch`. Families 5, 6, and 7 all cite it.
`CWE-390` detection of error without action, `CWE-703` improper check for exceptional conditions.

### A03:2025 and A08:2025

Software Supply Chain Failures and Software or Data Integrity Failures. Both real, both out of
scope here. See `supply-chain-security`.

## API Top 10 2023, where it fits better

Use the API list when the finding is about an HTTP endpoint. It is more specific than the Top 10
for authorization and resource consumption.

| Category | Use it for |
|---|---|
| API1 Broken Object Level Authorization | An endpoint that returns or edits an object by ID with no ownership check |
| API3 Broken Object Property Level Authorization | A body field the client should not be able to set: `role`, `price`, `isAdmin`, `credits` |
| API4 Unrestricted Resource Consumption | No pagination, no upload cap, no rate limit, no timeout, no spend ceiling |
| API5 Broken Function Level Authorization | An admin route reachable by a normal user because the check was only in the UI |
| API6 Unrestricted Access to Sensitive Business Flows | Automation abusing a legitimate flow: bulk signup, ticket buying, free-tier farming |
| API8 Security Misconfiguration | CORS wildcard, debug on, stack traces returned, TLS verification disabled |
| API10 Unsafe Consumption of APIs | Trusting a third-party response without validation or a size cap |

## Writing the citation

Name the category, the chapter, and the CWE, then the consequence in plain words. The standard
tells a reviewer where the finding sits; the consequence is what gets it fixed.

Example wording:

```text
Missing pagination on GET /api/customers (A06:2025 Insecure Design, API4:2023, ASVS V4,
CWE-770). One unauthenticated request loads every row into memory. At the current table size
that is a slow response; at ten times the size the process is killed and the app is down for
everyone.
```

Do not stack categories to make a finding look worse. One primary category, plus a second only
when it genuinely applies.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE list - <https://cwe.mitre.org/data/index.html>
