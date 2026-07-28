# Troubleshooting

What to do when a security test cannot be written, cannot be run, or cannot be trusted.

## The test passes before the fix

The most important failure, and the easiest to miss because the suite is green either way.

Diagnose in this order:

1. Is the assertion reachable? A `pytest.raises` block that never runs, or an `expect` after an
   early `return`, asserts nothing.
2. Is the assertion about the security property, or about a side effect? `status != 500` passes
   on a handler that returns the file.
3. Is the fixture already safe? A test user with no data cannot demonstrate cross-user read.
   Bob must own an object that actually exists.
4. Is the client bypassing the layer under test? An in-process test client that skips
   middleware will not see a middleware-enforced control, in either direction.

The mechanical check: revert the fix, run the test, confirm red, restore the fix. Do it with
`git stash` on the fix commit, not by hand-editing, so nothing is left behind.

## Cannot reproduce a scanner finding by hand

Common and usually explainable. Work through the differences before calling it a false positive.

| Difference | What to check |
|---|---|
| Authentication | The scanner may hold a session your `curl` does not, or vice versa |
| Encoding | The tool may double-encode. Compare the raw bytes on the wire, not the report text |
| Timing | A blind injection needs the delay payload and a slow enough response window |
| Endpoint | A rewrite rule or a trailing slash can route to different handlers |
| State | The finding may need a prior request in the same session |

If it still does not reproduce after that, record it as unreproducible with the evidence you
gathered and the tool's request ID. "Unreproducible, tool request logged, retested twice" is a
defensible outcome. Silently deleting it is not.

## The DAST scan is blocked by authentication

Baseline scans crawl what they can reach; behind a login, they reach the login page. Fix it in
this order:

1. Give the scanner a session. A pre-seeded cookie or a token in a header is simpler and more
   reliable than scripted form login.
2. Give it a route list. Import the OpenAPI or GraphQL schema so it does not depend on crawling.
3. Use a dedicated scan account with realistic but non-privileged permissions, and a second one
   in another tenant so cross-tenant findings are possible at all.

If none of that is available, say the scan covered unauthenticated surface only. That is a real
result about a real part of the attack surface, and it is not coverage of the rest.

## The test is flaky

A flaky security test gets skipped, and a skipped security test is a missing control. Fix the
flakiness rather than the tolerance.

| Cause | Fix |
|---|---|
| Time or ordering dependence | Freeze the clock, sort before comparing, isolate per test |
| Shared fixture mutated by another test | Function-scoped fixtures, fresh DB transaction per test |
| Real network call | Block outbound in the test environment and assert the block |
| Timing assertion for constant-time behaviour | Move it out of the gating suite. See below |
| Random fuzz input | Fixed seed in CI, corpus committed, unbounded runs nightly only |

Timing-based tests for constant-time comparison are inherently noisy on shared CI runners.
Assert the code path instead — that `secrets.compare_digest` or `crypto.timingSafeEqual` is what
runs — and keep statistical timing work out of the build gate.

## The vulnerability is real but the test would be destructive

Denial of service, resource exhaustion, and mass-delete tests can take down the environment they
run in. Options, in order of preference:

1. Test the control, not the failure. Assert the rate limiter returns 429 at the configured
   threshold; do not send a million requests.
2. Assert the bound exists. A test that a 200 MB upload is rejected at 10 MB does not need to
   send 200 MB — send 10 MB + 1 byte.
3. Run the destructive version in an isolated, disposable environment, in an authorized window,
   with the owner informed.

Never run a destructive test against production because the finding seemed important. See
[SKILL.md](SKILL.md#authorized-scope-first).

## Scope does not cover where the vulnerability is

You found something in a third-party component, a subdomain outside the target list, or a
provider's platform. Stop testing it.

1. Stop at the point of discovery. Do not enumerate further to characterise it.
2. Report it to the scope owner with what you already have.
3. Ask for scope to be extended in writing if characterising it matters.
4. For a third-party product, use the vendor's disclosure process, not your test suite.

Continuing because the finding looks serious converts a good-faith test into unauthorized access.

## The framework claims to test it for you

Some frameworks ship security test helpers, and some of those assert less than they appear to.
Verify what the helper actually checks: a CSRF test helper may confirm a token is present in the
form without confirming the server rejects a request that omits it.

Read the helper's implementation or its version documentation. If you cannot confirm what it
asserts, write the explicit test alongside it.

## A gate blocks on something that is not a vulnerability

A gate that fires on false positives gets disabled, so fix the gate rather than lowering the
bar globally.

1. Reproduce and confirm it is a false positive.
2. Suppress the specific rule at the specific location, with the reason and the date in the
   suppression file. Never a global rule disable, never a blanket severity threshold raise.
3. Set an expiry or a review date on the suppression.
4. If the same rule fires falsely across many files, the rule is misconfigured for this
   codebase. Retune it once instead of suppressing fifty times.

A suppression without a stated reason is indistinguishable from a bypass, and it will be read as
one during an audit.

## No test framework exists

Set up the standard choice for the language — pytest for Python, Jest or Vitest for
JavaScript/TypeScript — write the security test, and say what you added. If the environment
blocks installation, write the test anyway, mark it as unrun, and say so plainly rather than
implying it passed.

## A standard's ID cannot be confirmed

WSTG IDs and ASVS requirement numbers move between versions. WSTG v4.2 is from December 2020 and
5.0 is unreleased; ASVS 5.0.0 renumbered everything from 4.0.3.

Cite what you have verified. `ASVS V8 (Authorization)` at chapter level is honest;
a precise requirement ID you have not read is not. Fetch the source rather than recalling it:

- <https://owasp.org/www-project-web-security-testing-guide/v42/>
- <https://github.com/OWASP/ASVS>

The IDs in this skill were verified on 2026-07-28. Re-check before quoting them in an external
report.
