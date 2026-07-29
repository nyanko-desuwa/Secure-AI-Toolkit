# CWE Top 25 - 2025 Edition

Source: <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
Landing page: <https://cwe.mitre.org/top25/>
Verified: 2026-07-28. List page states "Page Last Updated: December 15, 2025".
Dataset: 39,080 CVE records.

The list ranks weakness classes by prevalence and severity in that CVE dataset. It is a
prioritisation input for a reviewer, not a checklist - rank 1 in the CVE corpus is not
necessarily rank 1 in your application.

## The ranked list

| Rank | CWE | Name | Reviewable by reading code? |
|---|---|---|---|
| 1 | CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | Yes |
| 2 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Yes |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) | Partly - needs config |
| 4 | CWE-862 | Missing Authorization | Yes |
| 5 | CWE-787 | Out-of-bounds Write | Memory safety |
| 6 | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Yes |
| 7 | CWE-416 | Use After Free | Memory safety |
| 8 | CWE-125 | Out-of-bounds Read | Memory safety |
| 9 | CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Yes |
| 10 | CWE-94 | Improper Control of Generation of Code ('Code Injection') | Yes |
| 11 | CWE-120 | Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | Memory safety |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | Yes |
| 13 | CWE-476 | NULL Pointer Dereference | Memory safety |
| 14 | CWE-121 | Stack-based Buffer Overflow | Memory safety |
| 15 | CWE-502 | Deserialization of Untrusted Data | Yes |
| 16 | CWE-122 | Heap-based Buffer Overflow | Memory safety |
| 17 | CWE-863 | Incorrect Authorization | Yes |
| 18 | CWE-20 | Improper Input Validation | Yes, but see below |
| 19 | CWE-284 | Improper Access Control | Yes, but see below |
| 20 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Yes |
| 21 | CWE-306 | Missing Authentication for Critical Function | Yes |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) | Yes |
| 23 | CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') | Yes |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | Yes |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling | Yes |

New to the 2025 list, with no 2024 rank: CWE-120, CWE-121, CWE-122, CWE-284. CWE-77 fell ten
places; CWE-476 rose eight.

Seven of the twenty-five are memory-safety weaknesses in C and C++. This skill's sink table
does not cover them. If you are reviewing native code, that is a different discipline with
different tooling and this skill is the wrong tool.

## Picking the right CWE

Pick the most specific class that describes the mistake, not the broadest one that fits. A
finding tagged CWE-20 tells the author nothing about what to change.

Work down, not up:

1. Name the sink. SQL, HTML, path, command, deserializer, HTTP client, authorization decision.
2. Name what went wrong at that sink. Missing check, wrong check, no encoding, wrong encoding.
3. Choose the CWE that combines both. `CWE-89` is "SQL sink, no neutralization". `CWE-639` is
   "authorization decision keyed on a value the client controls".

### The three that get overused

CWE-20 (Improper Input Validation) is a parent class. Almost every injection can be described
as failed input validation, which is exactly why it is the wrong answer - it points the fix at
the boundary when the fix belongs at the sink. Use CWE-20 only when validation genuinely is
the control: a numeric range that the business logic depends on, a length limit, a state
machine that accepts an out-of-order transition. If there is a sink, name the sink's CWE.

CWE-284 (Improper Access Control) is likewise a parent. Reach for a child:

| Situation | CWE |
|---|---|
| No authorization check exists on the handler at all | CWE-862 Missing Authorization |
| A check exists and is wrong - wrong role, wrong comparison, wrong order | CWE-863 Incorrect Authorization |
| The check reads an object key the client supplied | CWE-639 Authorization Bypass Through User-Controlled Key |
| No authentication at all on something that needs it | CWE-306 Missing Authentication for Critical Function |
| Authorization is enforced only in the client | CWE-602 Client-Side Enforcement of Server-Side Security |

CWE-200 (Exposure of Sensitive Information) gets applied to any response containing more
fields than necessary. If the extra fields belong to another user, the weakness is the
authorization failure that returned them, not the exposure. Use CWE-200 when the actor is
entitled to the object but not to those fields - a serializer leaking `password_hash` or
`internal_notes` on the user's own record. That is also API3:2023.

### Sink to CWE, the pairs that recur

| Sink and mistake | CWE | Top 10 2025 | ASVS 5.0 |
|---|---|---|---|
| SQL built by concatenation or f-string | CWE-89 | A05 | V1 |
| SQL identifier interpolated, values parameterized | CWE-89 | A05 | V1 |
| NoSQL query taking a raw object from the body | CWE-943 | A05 | V1 |
| Untrusted data in an HTML body or attribute | CWE-79 | A05 | V1, V3 |
| Untrusted data in a DOM sink (`innerHTML`) | CWE-79 | A05 | V3 |
| Untrusted data in a server-side template | CWE-1336 | A05 | V1 |
| Shell invoked with a built string | CWE-78 | A05 | V1 |
| Argument injection into a fixed binary | CWE-88 | A05 | V1 |
| `eval`, `new Function`, dynamic import of input | CWE-94 | A05 | V15 |
| `pickle.loads`, `yaml.load`, `ObjectInputStream` | CWE-502 | A08 | V15 |
| XML parser with external entities enabled | CWE-611 | A05 | V15 |
| Client path segment reaching the filesystem | CWE-22 | A01 | V5 |
| Archive entry written without checking its path | CWE-22 | A08 | V5 |
| Upload accepted on declared type or extension | CWE-434 | A08 | V5 |
| Outbound request to a client-supplied URL | CWE-918 | A06 | V2, V12 |
| Redirect target from a query parameter | CWE-601 | A01 | V3 |
| Object fetched by ID with no owner scoping | CWE-639 | A01 (API1) | V8 |
| Handler with no authorization decision | CWE-862 | A01 (API5) | V8 |
| Authorization decision present but incorrect | CWE-863 | A01 | V8 |
| Role or tenant read from the request body | CWE-639, CWE-602 | A01 | V8 |
| Extra sensitive fields in a serialized response | CWE-200 | A01 (API3) | V14 |
| Mass assignment from an unvalidated body | CWE-915 | A01 | V2 |
| JWT verified with the algorithm from the token | CWE-347 | A07 | V9 |
| Session not rotated on privilege change | CWE-384 | A07 | V7 |
| Password hashed with a fast hash | CWE-916 | A04 | V11 |
| Secret compared with `==` | CWE-208 | A04 | V11 |
| Hardcoded credential in source | CWE-798 | A04 | V14 |
| No limit on a user-controlled size or count | CWE-770 | A06 (API4) | V2 |
| Regex with catastrophic backtracking on free text | CWE-1333 | A06 | V2 |
| Security check that returns permissive on error | CWE-636 | A10 | V16 |
| Exception swallowed with an empty handler | CWE-390 | A10 | V16 |
| Stack trace or internal detail in a response | CWE-209 | A10 | V16 |
| Unescaped newlines from input written to a log | CWE-117 | A09 | V16 |
| Race between check and use | CWE-367 | A06 | V15 |

CWE-1336, CWE-943, CWE-88, CWE-915, CWE-602, CWE-209, CWE-367, CWE-384, CWE-798, CWE-208,
CWE-916, CWE-117, CWE-611, CWE-601, CWE-390, CWE-636 and CWE-1333 are not in the 2025 Top 25.
They are still the correct identifiers for those mistakes. Top 25 membership is a prevalence
signal, not a validity test.

## Related MITRE views worth knowing

- CWE Top 10 KEV Weaknesses (2025) - ranked from CISA's Known Exploited Vulnerabilities
  catalog: <https://cwe.mitre.org/top25/archive/2025/2025_kev_list.html>. Weight this above the
  main Top 25 when arguing exploitability, since every entry has confirmed exploitation.
- On the Cusp (2025) - 15 weaknesses that just missed the cut:
  <https://cwe.mitre.org/top25/archive/2025/2025_onthecusp_list.html>.

## Limitations of the list itself

- It is derived from CVE records, which over-represent software with a mature disclosure
  process and under-represent bespoke web applications, where BOLA and broken authorization
  dominate. OWASP API Security Top 10 2023 is the better prevalence signal for internal APIs.
- Rank mixes prevalence and severity. A rank-2 weakness in a codebase that has no SQL is
  irrelevant; do not order a review by this table.
- CWE mappings in CVE records are assigned inconsistently, so the ranking has known noise.
  MITRE documents this in the methodology page linked from the landing page.
