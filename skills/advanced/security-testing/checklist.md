# Security Testing Checklist

Run before returning a test suite, a pipeline change, or a test report. Mark each item pass,
fail, or not applicable. "Not applicable" needs a one-line reason.

Only the sections that match the work need running. A unit test for an HTML encoder does not
need the DAST section.

## Scope and Authorization

- [ ] Every target the tests reach is one you own or have written authorization for
- [ ] Environment named: local, CI, staging, or production. Production has separate sign-off
- [ ] Destructive and denial-of-service techniques either authorized in writing or excluded
- [ ] Third-party and SaaS surfaces excluded unless the provider's policy permits testing
- [ ] Abort contact and test window recorded for anything touching a shared environment

## Test Derivation

- [ ] Each test traces to an abuse case, a threat model entry, or a past finding
- [ ] Abuse cases cover cross-user, cross-tenant, volume, ordering, and replay, not just payloads
- [ ] Every fixed vulnerability has a regression test naming its CWE
- [ ] Tests cite a WSTG v4.2 ID or an ASVS chapter, so coverage claims are checkable
- [ ] Coverage gaps stated explicitly, not implied by absence

## The Test Actually Detects the Flaw

- [ ] Each security test was run against the vulnerable code and observed to fail
- [ ] Assertions check the security property, not just the status code or absence of a 500
- [ ] Negative assertions name the data that must be absent, not `not None`
- [ ] No test asserts on a payload being echoed back without checking the encoding context
- [ ] Tests fail for the right reason: check the failure message, not just the red

## Layer Choice

- [ ] Authorization tested at the HTTP layer, not only as a unit test of a policy helper
- [ ] Encoders, validators, and path resolvers tested at the unit layer where they are cheap
- [ ] DOM XSS and CSP tested in a real browser, not by string matching the response body
- [ ] Nothing is tested only through the UI that could be tested through the API

## Authorization Matrix

- [ ] Matrix lists every role including anonymous, and every operation including delete
- [ ] Cross-tenant cells asserted, not assumed
- [ ] Nonexistent-object cells asserted to be indistinguishable from not-yours
- [ ] Write, update, and delete covered separately from read
- [ ] Tests generated from the matrix, so adding a role adds assertions

## Property and Fuzz Testing

- [ ] The property is an invariant, not a payload list
- [ ] Seeds recorded and failing cases committed as explicit regression cases
- [ ] Time or example budget bounded in CI, unbounded runs scheduled separately
- [ ] Crashes and unhandled exceptions treated as failures, not filtered as noise

## Test Data Safety

- [ ] No production data, exports, or database dumps in fixtures
- [ ] No real credentials, tokens, or API keys, including expired ones
- [ ] Placeholder identities and reserved example domains only
- [ ] Payload files that mimic malware or exploit archives are inert and documented
- [ ] Test artefacts, screenshots, and HAR files scrubbed before upload to CI storage

## CI Execution

- [ ] Security tests run on every push, in the same job as the rest of the suite
- [ ] Secret scanning covers history, not only the diff
- [ ] Gating policy explicit: which checks block, which warn, and who can override
- [ ] Scanner baselines committed, so a new finding is distinguishable from a known one
- [ ] Scan credentials come from the CI secret store, never from the repository
- [ ] Pipeline failures on the security job are not retried automatically until green

## Triage

- [ ] Every scanner result reproduced by hand before being reported
- [ ] False positives recorded with the reason, so the rule can be tuned or suppressed narrowly
- [ ] Suppressions are per-finding with an expiry or a review date, never a whole rule
- [ ] Severity assigned from exploitability and blast radius, not copied from the tool

## Before Returning

- [ ] Test suite run, with output reported honestly including skips
- [ ] Each new security test confirmed to fail on the unfixed code, or the reason stated
- [ ] Flaky tests fixed or quarantined with an owner, not deleted
- [ ] Temporary files, scan reports, and fixture uploads removed
- [ ] What was not tested stated plainly
