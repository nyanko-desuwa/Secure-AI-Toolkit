# CWE, mapped to the test that proves it

Ranks are from the 2025 CWE Top 25 Most Dangerous Software Weaknesses, derived from 39,080 CVE
records. Verified against <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html> on
2026-07-28.

A CWE in a test name is the durable part of the citation. Top 10 categories are renumbered
between editions and WSTG IDs move between releases; CWE-639 has meant the same thing for
years.

## 2025 CWE Top 25, with the test that would catch each

| Rank | CWE | Name | Test type that detects it |
|---|---|---|---|
| 1 | CWE-79 | Cross-site Scripting | Browser test asserting no script execution |
| 2 | CWE-89 | SQL Injection | Behavioural integration test on the result set |
| 3 | CWE-352 | Cross-Site Request Forgery | Integration test: cross-origin state change |
| 4 | CWE-862 | Missing Authorization | Authorization matrix |
| 5 | CWE-787 | Out-of-bounds Write | Sanitizer build plus coverage-guided fuzzing. Not covered here |
| 6 | CWE-22 | Path Traversal | Property test over the whole input space |
| 7 | CWE-416 | Use After Free | Sanitizer build. Not covered here |
| 8 | CWE-125 | Out-of-bounds Read | Sanitizer build. Not covered here |
| 9 | CWE-78 | OS Command Injection | Integration test asserting no subprocess spawned |
| 10 | CWE-94 | Code Injection | Integration test asserting no evaluation side effect |
| 11 | CWE-120 | Classic Buffer Overflow | Sanitizer build. Not covered here |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | Upload test with real file bytes |
| 13 | CWE-476 | NULL Pointer Dereference | Fuzzing with a crash oracle. Not covered here |
| 14 | CWE-121 | Stack-based Buffer Overflow | Sanitizer build. Not covered here |
| 15 | CWE-502 | Deserialization of Untrusted Data | Integration test with a hostile serialized payload |
| 16 | CWE-122 | Heap-based Buffer Overflow | Sanitizer build. Not covered here |
| 17 | CWE-863 | Incorrect Authorization | Matrix, specifically the non-happy-path cells |
| 18 | CWE-20 | Improper Input Validation | Property test on the validator |
| 19 | CWE-284 | Improper Access Control | Matrix across the whole component, not one endpoint |
| 20 | CWE-200 | Exposure of Sensitive Information | Response-shape assertions on field allowlists |
| 21 | CWE-306 | Missing Authentication for Critical Function | Anonymous row of the matrix |
| 22 | CWE-918 | Server-Side Request Forgery | Test asserting the outbound request was never sent |
| 23 | CWE-77 | Command Injection | Integration test asserting no subprocess spawned |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | IDOR test, cross-user |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling | Rate limit and size limit tests |

Four entries are new to the 2025 list: CWE-120, CWE-121, CWE-122, and CWE-284. CWE-77 dropped
ten places; CWE-476 climbed eight.

Seven of the twenty-five are memory-safety weaknesses (787, 416, 125, 120, 476, 121, 122).
Testing them means sanitizer builds and coverage-guided fuzzing of native code, which is a
different discipline from what this skill covers. Do not read their absence here as low
importance.

## Weaknesses outside the Top 25 worth a test

These recur in web applications and each has a cheap, specific test.

| CWE | Name | Test |
|---|---|---|
| CWE-611 | XML External Entity Reference | Parse a document with an external entity, assert no fetch and no file read |
| CWE-601 | Open Redirect | Assert an off-site `next` parameter is rejected, not followed |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Post a privileged field, assert it did not persist |
| CWE-1333 | Inefficient Regular Expression Complexity | Property test with a time budget on the matcher |
| CWE-400 | Uncontrolled Resource Consumption | Size, depth, and count limits asserted at the boundary |
| CWE-636 | Not Failing Securely | Fault injection: make the dependency fail, assert denial |
| CWE-390 | Detection of Error Condition Without Action | Same fault injection, assert the error surfaced |
| CWE-347 | Improper Verification of Cryptographic Signature | Tamper with a token, assert rejection; also `alg: none` |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | Unit test on the verifier's accepted formats |
| CWE-208 | Observable Timing Discrepancy | Assert the constant-time function is used, not the timing |
| CWE-117 | Improper Output Neutralization for Logs | Log-capturing test with a newline in the input |
| CWE-1336 | Server-Side Template Injection | Integration test with a template expression payload |
| CWE-1104 | Use of Unmaintained Third Party Components | Dependency scan in CI |
| CWE-328 | Use of Weak Hash | Only where a security property depends on the digest |

## Choosing the CWE for a test name

The pairs that get confused, and the question that separates them:

| If | Then |
|---|---|
| No authorization decision exists on the path | CWE-862 Missing Authorization |
| A decision exists and is wrong — wrong operator, wrong role, wrong order | CWE-863 Incorrect Authorization |
| The decision uses an identifier the client supplied | CWE-639 |
| Access control is structurally absent across a component | CWE-284 |
| The sink is SQL | CWE-89, not the generic CWE-20 |
| The sink is a shell with an OS command | CWE-78 |
| The sink is a shell metacharacter in any command context | CWE-77 |
| Untrusted data becomes code in the application's own language | CWE-94 |
| A file path leaves its directory | CWE-22 |
| Data is returned that the actor should not see, with authorization intact | CWE-200 |

CWE-20 (Improper Input Validation) is a class, not a diagnosis. Use it only when the weakness
genuinely is a missing or wrong validator and no downstream sink is identified. If you can name
the sink, name the sink's CWE.

## Format for a test name

```python
def test_password_reset_token_is_single_use():
    """WSTG-ATHN-09 · CWE-640 family · ASVS V6. Regression for #2213.

    Confirmed failing on 91af330: second POST with the same token returned 200.
    """
```

Three things make this durable: the CWE survives standard renumbering, the commit hash records
that a red run happened, and the test name describes the attacker behaviour rather than the
implementation. A test called `test_token_marked_used_flag` breaks when the column is renamed
and tells a future reader nothing about what it protects.

If you are unsure of a specific CWE number, cite the family in prose or leave it out. An
invented CWE ID is worse than no ID, because someone will look it up and act on the wrong
weakness.

## Sources

- 2025 CWE Top 25 — <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- CWE Top 25 landing page — <https://cwe.mitre.org/top25/>
- CWE list — <https://cwe.mitre.org/data/index.html>
- OWASP WSTG v4.2 — <https://owasp.org/www-project-web-security-testing-guide/v42/>
