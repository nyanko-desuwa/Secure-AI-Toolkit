---
name: security-testing
description: 'Write and run security tests that fail when the vulnerability is present: threat-derived cases, authorization matrices, property and fuzz tests, DAST in CI, and triage of false positives. Maps to OWASP WSTG v4.2 and ASVS 5.0. Triggers: "security test", "pentest", "fuzzing", "DAST", "authorization matrix", "abuse case", "kiểm thử bảo mật", "kiểm tra lỗ hổng".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Security Testing

A security test earns its place by failing on vulnerable code. Most do not: they assert a 200,
or they assert that a payload was rejected in a way the fix never actually changed. This skill
is about writing tests that would have caught the bug, and running them where they keep
working.

## When to Use

- Adding tests for a vulnerability you just fixed
- Building an authorization test matrix for an API
- Deciding which layer a security test belongs in
- Wiring SAST, DAST, or dependency scanning into CI and choosing what gates the build
- Triaging scanner output into findings and false positives
- Turning a threat model or abuse case into executable tests

Use `core/secure-code-review` to find the bug by reading. Use this skill to prove it exists,
and to stop it coming back.

## Authorized Scope First

Testing that reaches a live system needs authorization in writing before the first request.
This is not a formality: unauthorized scanning is a criminal offence in many jurisdictions,
and a load test against production is an outage.

Establish and record five things:

| Item | Why it matters |
|---|---|
| Targets | Exact hostnames, IP ranges, and accounts. Anything not listed is out of scope |
| Environment | Staging or production. Production needs separate, explicit sign-off |
| Techniques allowed | Passive, active injection, credential attacks, denial of service - each named |
| Window | Start and end time, plus who is on call |
| Contact | Who to call when a test causes an incident, and how to abort |

Rules that follow:

- Unit, integration, and property tests against your own code and your own local
  infrastructure need no authorization beyond normal engineering practice.
- DAST against a shared environment needs the owner's agreement, not just yours.
- Third-party assets are out of scope by default. A SaaS provider's login page is theirs even
  if you paid for the tenant. Check the provider's testing policy.
- Never use production data as test data. See [best-practices.md](best-practices.md#test-data-safety).

Stop and ask if scope is unclear. An out-of-scope finding cannot be reported and cannot be
fixed, so the test was worse than useless.

## Workflow

### 1. Derive tests from threats, not from coverage

Coverage-driven testing produces tests for the code that exists. Security testing needs tests
for the requests an attacker sends, which by definition are not in the code.

Start from three sources:

- Abuse cases. For each use case, write the misuse: "user exports their own data" becomes
  "user exports another tenant's data", "user exports 40 GB", "user exports 10,000 times".
- The threat model, if one exists. Every trust boundary crossing gets at least one test.
- Past findings. Every fixed vulnerability gets a regression test that fails on the old code.

Map each to a WSTG test ID so the coverage claim is checkable. See
[references/wstg-4.2.md](references/wstg-4.2.md).

### 2. Build the authorization matrix

Access control is the largest category in every Top 10 edition and the easiest to test
exhaustively, because it is a finite grid: roles down, operations across, expected outcome in
each cell.

| Actor | Own object | Other user, same tenant | Other tenant | Nonexistent |
|---|---|---|---|---|
| Anonymous | 401 | 401 | 401 | 401 |
| User | 200 | 404 | 404 | 404 |
| Tenant admin | 200 | 200 | 404 | 404 |
| Support staff | 200 (audited) | 200 (audited) | 404 | 404 |

Then generate the tests from the grid rather than writing them one at a time. A matrix with
four actors and six operations is 24 assertions; hand-written, it becomes six tests for the
happy path. See [best-practices.md](best-practices.md#authorization-matrix-testing).

Note that "other user" returns 404, not 403 - the matrix encodes existence non-disclosure, so
the test enforces it. WSTG-ATHZ-02, WSTG-ATHZ-04, ASVS V8.

### 3. Test at the cheapest layer that can fail

Push each test down until it can no longer detect the flaw. Layer choice decides whether the
test survives the next refactor.

| Layer | Detects | Cost | Blind to |
|---|---|---|---|
| Unit | Encoder, validator, and crypto helper behaviour | Milliseconds | Whether the helper is called |
| Integration (HTTP) | Authorization, session, error handling, status codes | Seconds | Client-side execution |
| Property / fuzz | Input classes you did not think of, parser crashes | Minutes | Semantic authorization |
| Browser (E2E) | DOM XSS, CSP, cookie flags in a real client | Minutes | Server internals |
| DAST | Deployed configuration, headers, TLS, unlinked endpoints | Minutes to hours | Business logic, multi-step auth |

The common failure is testing authorization at the unit layer. A unit test of
`canAccess(user, doc)` passes while the handler never calls it. Authorization tests belong at
the HTTP layer, where the request is what the attacker actually sends.

### 4. Fuzz where the input space is larger than your imagination

Example-based tests check the payloads you thought of. Property-based and fuzz tests check the
space. Use them where a parser, a path resolver, a URL validator, or a template renderer takes
free-form input.

The property is the invariant, not the payload: "no input to `resolve_upload_path` returns a
path outside the upload directory" holds for every string, including the encodings you have
not heard of. See [best-practices.md](best-practices.md#property-and-fuzz-testing).

### 5. Run it in CI, and decide what blocks

A security test suite that is not in CI is documentation. One that blocks the build on every
informational finding gets disabled within a month.

| Check | Runs | Blocks the build |
|---|---|---|
| Security unit and integration tests | Every push | Yes, always |
| Secret scanning | Every push, plus full history | Yes |
| SAST | Every PR, diff-scoped | Yes on high confidence, warn otherwise |
| Dependency scan | Every PR and nightly | Yes on known-exploited or reachable critical |
| Property / fuzz, short run | Every PR, fixed seed and time budget | Yes on a crash or new failure |
| Fuzz, long run | Nightly or weekly | No. Files an issue |
| DAST baseline | Post-deploy to staging | Yes on new high findings vs baseline |
| DAST full active scan | Scheduled, authorized window | No. Reviewed by a human |

See [best-practices.md](best-practices.md#ci-execution) for the pipeline shape and
[troubleshooting.md](troubleshooting.md) for what to do when a gate is wrong.

### 6. Triage before reporting

Every scanner result is a candidate, not a finding. Reproduce it by hand, in the same
environment, with a request you wrote yourself. If you cannot reproduce it, it is not a
finding yet.

For each candidate: is the sink real, is the source attacker-controlled, does the impact
exist, and can you write the request? A candidate that fails any of those is a false positive
or an observation. See [common-mistakes.md](common-mistakes.md#treating-scanner-output-as-findings).

## Severity

Rate what the test proves, not what the tool called it. Exploitability multiplied by blast
radius.

- Critical - a test demonstrates unauthenticated access to other users' data, or code
  execution
- High - a test demonstrates authenticated cross-tenant or cross-user access, or injection
  behind auth
- Medium - exploitation needs an unlikely precondition, or the leak is non-sensitive
- Low - a hardening gap the test detects with no demonstrated path
- Informational - the test asserts a defence-in-depth control that is absent

Two rules specific to testing:

- A failing test is not automatically a vulnerability. It may be a wrong test. Confirm the
  behaviour manually before filing.
- A passing test proves only what it asserts. State the coverage gap: "authorization tested
  for the REST API; the GraphQL resolver path is untested".

## Related Skills

- `core/secure-code-review` - finding the bug by reading, and CWE assignment
- `core/devsecops` - the CI platform, gating policy, and secret scanning depth
- `core/api-security` - API weakness classes worth building matrices for
- `advanced/incident-response` - what happens when a test finds it in production

## Supporting Files

- [README.md](README.md) - purpose, layout, standards, limitations
- [checklist.md](checklist.md) - pre-return verification for a test suite
- [best-practices.md](best-practices.md) - patterns, with weak and strong test pairs
- [common-mistakes.md](common-mistakes.md) - tests that pass on vulnerable code
- [troubleshooting.md](troubleshooting.md) - flaky tests, blocked scope, wrong gates
- [prompts.md](prompts.md) - prompts that produce tests, and anti-patterns
- [references/](references/) - WSTG v4.2, ASVS 5.0.0, Top 10 2025, CWE
- [examples/](examples/) - eight weak/strong test pairs with WSTG and CWE IDs
