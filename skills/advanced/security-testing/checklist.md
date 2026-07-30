# Security Testing Checklist

Run before returning a test suite, a pipeline change, or a test report. Mark each item pass,
fail, or not applicable. "Not applicable" needs a one-line reason.

Only the sections that match the work need running. A unit test for an HTML encoder does not
need the DAST section.

## Scope and Authorization

- [ ] [critical] Every target the tests reach is one you own or have written authorization for
- [ ] [critical] Environment named: local, CI, staging, or production. Production has separate sign-off
- [ ] [critical] Destructive and denial-of-service techniques either authorized in writing or excluded
- [ ] [critical] Third-party and SaaS surfaces excluded unless the provider's policy permits testing
- [ ] [recommended] Abort contact and test window recorded for anything touching a shared environment

## Test Derivation

- [ ] [recommended] Each test traces to an abuse case, a threat model entry, or a past finding
- [ ] [recommended] Abuse cases cover cross-user, cross-tenant, volume, ordering, and replay, not just payloads
- [ ] [recommended] Every fixed vulnerability has a regression test naming its CWE
- [ ] [recommended] Tests cite a WSTG v4.2 ID or an ASVS chapter, so coverage claims are checkable
- [ ] [recommended] Coverage gaps stated explicitly, not implied by absence

## The Test Actually Detects the Flaw

- [ ] [critical] Each security test was run against the vulnerable code and observed to fail
- [ ] [critical] Assertions check the security property, not just the status code or absence of a 500
- [ ] [recommended] Negative assertions name the data that must be absent, not `not None`
- [ ] [recommended] No test asserts on a payload being echoed back without checking the encoding context
- [ ] [recommended] Tests fail for the right reason: check the failure message, not just the red

## Layer Choice

- [ ] [critical] Authorization tested at the HTTP layer, not only as a unit test of a policy helper
- [ ] [recommended] Encoders, validators, and path resolvers tested at the unit layer where they are cheap
- [ ] [recommended] DOM XSS and CSP tested in a real browser, not by string matching the response body
- [ ] [optional] Nothing is tested only through the UI that could be tested through the API

## Authorization Matrix

- [ ] [critical] Matrix lists every role including anonymous, and every operation including delete
- [ ] [critical] Cross-tenant cells asserted, not assumed
- [ ] [critical] Nonexistent-object cells asserted to be indistinguishable from not-yours
- [ ] [critical] Write, update, and delete covered separately from read
- [ ] [recommended] Tests generated from the matrix, so adding a role adds assertions

## Property and Fuzz Testing

- [ ] [recommended] The property is an invariant, not a payload list
- [ ] [recommended] Seeds recorded and failing cases committed as explicit regression cases
- [ ] [recommended] Time or example budget bounded in CI, unbounded runs scheduled separately
- [ ] [recommended] Crashes and unhandled exceptions treated as failures, not filtered as noise

## Test Data Safety

- [ ] [critical] No production data, exports, or database dumps in fixtures
- [ ] [critical] No real credentials, tokens, or API keys, including expired ones
- [ ] [recommended] Placeholder identities and reserved example domains only
- [ ] [recommended] Payload files that mimic malware or exploit archives are inert and documented
- [ ] [recommended] Test artefacts, screenshots, and HAR files scrubbed before upload to CI storage

## CI Execution

- [ ] [recommended] Security tests run on every push, in the same job as the rest of the suite
- [ ] [recommended] Secret scanning covers history, not only the diff
- [ ] [recommended] Gating policy explicit: which checks block, which warn, and who can override
- [ ] [recommended] Scanner baselines committed, so a new finding is distinguishable from a known one
- [ ] [critical] Scan credentials come from the CI secret store, never from the repository
- [ ] [recommended] Pipeline failures on the security job are not retried automatically until green

## Triage

- [ ] [recommended] Every scanner result reproduced by hand before being reported
- [ ] [recommended] False positives recorded with the reason, so the rule can be tuned or suppressed narrowly
- [ ] [recommended] Suppressions are per-finding with an expiry or a review date, never a whole rule
- [ ] [recommended] Severity assigned from exploitability and blast radius, not copied from the tool

## Before Returning

- [ ] [critical] Test suite run, with output reported honestly including skips
- [ ] [critical] Each new security test confirmed to fail on the unfixed code, or the reason stated
- [ ] [recommended] Flaky tests fixed or quarantined with an owner, not deleted
- [ ] [recommended] Temporary files, scan reports, and fixture uploads removed
- [ ] [critical] What was not tested stated plainly
