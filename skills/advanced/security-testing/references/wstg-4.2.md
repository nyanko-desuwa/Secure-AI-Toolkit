# OWASP Web Security Testing Guide v4.2

Version v4.2, released 2020-12-03. This is the current numbered release. Verified against
<https://owasp.org/www-project-web-security-testing-guide/> and the individual v4.2 test pages
on 2026-07-28.

Version 5.0 is in active development and unreleased. A 4.3 placeholder exists in the project
repository but is not a release. The project also publishes a `stable` link that tracks the
newest content and therefore moves; cite a versioned URL (`/v42/`) so a report stays accurate.

## What WSTG is for

WSTG is a catalogue of tests. ASVS says what must be true; WSTG says how to check it. Neither
is a risk ranking - that is the Top 10.

In a test suite, a WSTG ID is the most useful citation available, because it names a procedure
rather than a property. `test_orders_idor` says nothing; `test_idor_orders__WSTG_ATHZ_04` tells
a reviewer which catalogue entry the test claims to cover.

## Identifier format

`WSTG-<CATEGORY>-<NN>` where the category is a four-character uppercase code and `NN` is
zero-padded, 01 to 99. Example: `WSTG-ATHZ-04`.

WSTG's own guidance is to use the versioned form in external reports and tooling, with
punctuation stripped from the version: `WSTG-v42-ATHZ-04`. An ID without a version element
means "the latest content", which is a moving target.

This skill writes the short form in prose and states the version once, here. If you publish a
finding outside your team, expand it to the versioned form.

## Categories in section 4, Web Application Security Testing

| Code | Chapter | Tests | Typical automation |
|---|---|---|---|
| INFO | 4.1 Information Gathering | 10 | DAST spider, manual recon |
| CONF | 4.2 Configuration and Deployment Management | 11 | DAST, infra-as-code checks |
| IDNT | 4.3 Identity Management | 5 | Integration tests |
| ATHN | 4.4 Authentication | 10 | Integration tests |
| ATHZ | 4.5 Authorization | 4 | Integration tests, matrix-generated |
| SESS | 4.6 Session Management | 9 | Integration tests, browser tests |
| INPV | 4.7 Input Validation | 19 | Unit, property, fuzz, DAST |
| ERRH | 4.8 Error Handling | 2 | Integration tests |
| CRYP | 4.9 Weak Cryptography | 4 | Unit tests, TLS scanner |
| BUSL | 4.10 Business Logic | 9 | Integration tests. Least automatable |
| CLNT | 4.11 Client-side | 13 | Browser tests |
| APIT | 4.12 API Testing | 1 | Integration tests |

Section 4.0 is the introduction. Sections 1 to 3 cover the testing framework, and sections 5
and 6 cover reporting and appendices; they carry no test IDs.

## IDs used in this skill

Every entry below was read from its v4.2 page rather than recalled.

| ID | Title | Where this skill uses it |
|---|---|---|
| WSTG-CONF-04 | Review Old Backup and Unreferenced Files for Sensitive Information | Why DAST finds what tests cannot |
| WSTG-CONF-07 | Test HTTP Strict Transport Security | DAST baseline header assertions |
| WSTG-IDNT-04 | Testing for Account Enumeration and Guessable User Account | Uniform-response tests |
| WSTG-ATHN-04 | Testing for Bypassing Authentication Schema | Anonymous row of the matrix |
| WSTG-ATHN-09 | Testing for Weak Password Change or Reset Functionalities | Reset token single-use test |
| WSTG-ATHZ-01 | Testing Directory Traversal File Include | Path traversal property test |
| WSTG-ATHZ-02 | Testing for Bypassing Authorization Schema | Authorization matrix |
| WSTG-ATHZ-03 | Testing for Privilege Escalation | Role rows of the matrix, mass assignment |
| WSTG-ATHZ-04 | Testing for Insecure Direct Object References | IDOR regression tests |
| WSTG-SESS-02 | Testing for Cookies Attributes | Cookie flag assertions |
| WSTG-SESS-05 | Testing for Cross Site Request Forgery | CSRF integration tests |
| WSTG-SESS-06 | Testing for Logout Functionality | Session invalidation tests |
| WSTG-INPV-01 | Testing for Reflected Cross Site Scripting | Reflected XSS tests |
| WSTG-INPV-02 | Testing for Stored Cross Site Scripting | Stored XSS tests |
| WSTG-INPV-05 | Testing for SQL Injection | SQLi behavioural tests |
| WSTG-INPV-19 | Testing for Server-Side Request Forgery | SSRF tests with an egress assertion |
| WSTG-ERRH-01 | Testing for Improper Error Handling | Error-shape tests |
| WSTG-CRYP-04 | Testing for Weak Encryption | Password hashing unit tests |
| WSTG-BUSL-01 | Test Business Logic Data Validation | Abuse-case derivation |
| WSTG-BUSL-04 | Test for Process Timing | Timing and race tests, and their flakiness |
| WSTG-BUSL-05 | Test Number of Times a Function Can Be Used Limits | Rate limit tests |
| WSTG-BUSL-08 | Test Upload of Unexpected File Types | File upload type tests |
| WSTG-BUSL-09 | Test Upload of Malicious Files | File upload content tests |
| WSTG-CLNT-01 | Testing for DOM-Based Cross Site Scripting | Browser-layer XSS tests |
| WSTG-APIT-01 | Testing GraphQL | Coverage gap when only REST is tested |

WSTG-INPV-05 has language-specific sub-entries (Oracle, MySQL, SQL Server, PostgreSQL, MS
Access, NoSQL, ORM, client-side) numbered 5.1 to 5.8 in the contents. Cite the parent ID unless
the test is engine-specific.

## How to cite WSTG in a test

Put the ID in the test name or a docstring, not only in a commit message. The name survives;
the commit message is not read again.

```python
def test_other_users_order_is_not_readable(client, alice, bobs_order):
    """WSTG-ATHZ-04 · CWE-639 · ASVS V8. Fails before the owner filter exists."""
    resp = client.get(f"/api/orders/{bobs_order.id}", headers=auth(alice))
    assert resp.status_code == 404
    assert str(bobs_order.total_cents) not in resp.text
```

A coverage claim then becomes checkable: grep the suite for WSTG IDs and diff against the list
you intended to cover.

```bash
rg -o 'WSTG-[A-Z]{4}-\d{2}' tests/ | sort -u
```

## What WSTG does not give you

- No severity. WSTG tells you how to test, not how bad the result is. Rate findings yourself.
- No pass criteria in machine-readable form. Each entry is prose with example payloads; turning
  it into an assertion is your work, and the assertion is where suites go wrong.
- Nothing on mobile or thick clients. MASTG is the mobile equivalent.
- Age. v4.2 is from December 2020, so newer surfaces are thin: there is one API entry
  (GraphQL), nothing on gRPC, and nothing on LLM or prompt-injection testing. Absence from
  WSTG is not evidence that a surface is safe.
- No CI guidance. WSTG assumes a tester, not a pipeline.

## Sources

- WSTG project page - <https://owasp.org/www-project-web-security-testing-guide/>
- WSTG v4.2 contents - <https://owasp.org/www-project-web-security-testing-guide/v42/>
- WSTG GitHub - <https://github.com/OWASP/wstg>
