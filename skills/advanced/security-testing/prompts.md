# Prompt Examples

Prompts that produce tests you can run, rather than a lecture on testing. Each names the target,
the standard, and the property the test must have.

## Regression test for a fix

```
I fixed an IDOR in src/api/orders.py by adding an owner filter to the query. Write the pytest
regression test. It must fail on the pre-fix code, assert 404 rather than 403, and assert that
no field of the other user's order appears in the response body.
```

Why it works: states the fix, the layer, and two specific assertions. Asking for "fails on the
pre-fix code" is what stops a test that asserts only a non-500.

## Authorization matrix

```
Build an authorization matrix for /api/projects/{id}. Actors: anonymous, member, project admin,
org admin, user from another org. Operations: read, list, update, delete, invite. Give me the
grid first, then parameterized tests generated from it. Every cell must have an expected status.
```

The grid first matters. If the model writes tests directly it covers the diagonal and misses the
cross-tenant cells, which are the ones that find bugs.

## Property test for a path resolver

```
Write a Hypothesis property test for resolve_upload_path(name) in src/files.py. The property is
that the returned path is always inside UPLOAD_DIR or the call raises. Generate arbitrary text,
not a payload list. Add the traversal encodings as explicit examples so they are always run.
```

Naming the invariant rather than the payloads is the difference between a property test and a
parameterized example test with extra machinery.

## SSRF test

```
Write an integration test for the URL preview endpoint that proves it never sends a request to
a private address. Patch the HTTP transport so an outbound connection fails the test, and cover
169.254.169.254, localhost, 10.x, a decimal-encoded IP, and a redirect from an allowed host to
a private one.
```

The "patch the transport so a request fails the test" instruction is the load-bearing part.
Without it the test asserts a 400 that a network timeout also produces.

## Turn a threat model into tests

```
Here is the threat model for our password reset flow. For each threat, write the test that would
detect it, name the layer it belongs in, and give the WSTG v4.2 ID. If a threat cannot be tested
automatically, say so and describe the manual test.
```

Asking which threats cannot be automated is what keeps the answer honest instead of producing a
test for everything and asserting nothing.

## Triage a scanner result

```
ZAP flagged reflected XSS at /search?q=. Give me the exact curl that would confirm it, three
reasons it might be a false positive, and the test to add if it is real. Do not assume it is
real.
```

## CI gating policy

```
We run pytest, Semgrep, gitleaks, pip-audit, and a ZAP baseline scan. Tell me which of these
should block a PR, which should warn, and which should run nightly. Justify each, and say what
happens when a gate fires on a false positive.
```

## Abuse cases from a feature description

```
Feature: users export their own transactions as CSV, emailed as a link. Write the abuse cases
before any tests. Cover other users' data, size, frequency, the link's lifetime, and what the
CSV content does in a spreadsheet application.
```

The last clause pulls out CSV formula injection, which almost nobody lists unprompted.

## Check an existing suite honestly

```
Read tests/security/. For each test, tell me whether it would fail if the control it targets
were removed. List the ones that would still pass, and what to change.
```

The best single prompt to run against an inherited suite. Expect a third of the tests to be
decorative.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Write security tests for this file" | No threat, no layer. Produces input validation tests for a config loader |
| "Add a pentest to CI" | Conflates DAST, SAST, and manual testing. Ask for a specific check |
| "Test for all the OWASP Top 10" | Half the categories are not unit-testable. Produces stubs |
| "Fuzz this API" | Without an invariant, a fuzzer only finds 500s. Name the property |
| "Make the security tests pass" | Invites weakening the assertion instead of fixing the code |
| "Scan example.com for vulnerabilities" | Not yours. Scope authorization is a precondition, not a detail |
| "Increase security test coverage to 80%" | Coverage measures code executed, not threats covered |
