# Common Mistakes

Ways a security test suite ends up green on vulnerable code. Each entry: what it looks like,
why it fails, and the fix.

## The test passes on the unfixed code

```python
def test_no_idor(client, bob):
    resp = client.get("/api/invoices/1", headers=bob.auth)
    assert resp.status_code in (200, 403, 404)
```

Every possible response satisfies that assertion. This is the base case of the whole file: the
test was written after the fix, against the fixed code, and never run against the vulnerable
version.

Fix: check out the pre-fix commit, or revert the one-line control, and run the test. If it
passes, it is not a regression test. Do this once per finding — it takes a minute and it is the
only proof the test has value.

## Authorization tested at the unit layer

```python
def test_can_access():
    assert can_access(bob, alice_invoice) is False
```

`can_access` is correct and the handler never calls it. The unit test passes forever while the
endpoint serves the object to anyone.

Fix: test authorization over HTTP, with a real session, against the real route. Keep the unit
test if you like, but it is a test of a helper, not of access control. WSTG-ATHZ-02 is a
request-level test for exactly this reason.

## Asserting on error text instead of behaviour

```python
assert "syntax error" in resp.text.lower()
```

Two failures in one line. The string changes when the driver is upgraded, and more importantly a
SQL syntax error means the payload reached the SQL parser. The endpoint is injectable; the test
is celebrating.

Fix: assert the input was rejected at the boundary (400), assert the database state is unchanged,
and assert no engine detail reaches the client. See
[best-practices.md](best-practices.md#injection-tests-assert-behaviour-not-error-text).

## A network failure in CI reads as a control

```python
resp = client.post("/fetch", json={"url": "http://169.254.169.254/"})
assert resp.status_code != 200
```

Nothing listens on that address in the CI network, so the request times out and the handler
returns 502. The test passes with no SSRF protection whatsoever, and keeps passing right up to
the day it runs somewhere with a metadata service.

Fix: assert the outbound client was never called. `mock.call_count == 0` is the property; the
status code is a side effect. See
[best-practices.md](best-practices.md#ssrf-tests-must-assert-the-request-was-never-sent).

## Testing the declared content type instead of the bytes

```python
client.post("/avatar", files={"f": ("x.php", b"<?php ?>", "application/x-php")})
```

The vulnerability is that the server trusts `Content-Type`. Sending an honest one exercises the
happy path of the broken check. The attacker declares `image/png`.

Fix: send real magic bytes with mismatched names, and send hostile bytes with an honest-looking
declared type. Then inspect what was stored. WSTG-BUSL-08, WSTG-BUSL-09.

## Escaping asserted in the wrong context

```javascript
expect(res.text).not.toContain("<script>");
```

Passes against `<img src=x onerror=alert(1)>`, against `javascript:` in an `href`, against a
payload in an unquoted attribute, and against every DOM sink. The single-payload check tests one
shape of one class.

Fix: match the assertion to the sink. HTML body, attribute, URL, and JavaScript contexts each
need their own case, and DOM sinks need a browser. See
[best-practices.md](best-practices.md#test-dom-xss-in-a-browser-not-with-string-matching).

## Only the happy path of the matrix

Six endpoints, six tests, each logging in as the owner and asserting 200. Coverage looks
complete. Nothing tests another user, another tenant, or an anonymous caller, and delete is
never tested at all because the fixture would need rebuilding.

Fix: generate tests from a matrix so the denial cells exist by construction. Read, update, and
delete are separate rows, because they are separately authorized in the code.

## Sharing state between security tests

```python
def test_admin_can_promote(client, admin):
    client.post("/users/5/promote", headers=admin.auth)

def test_user_cannot_promote(client, alice):
    resp = client.post("/users/5/promote", headers=alice.auth)
    assert resp.status_code == 403
```

The second test passes because user 5 is already an admin from the first one, and the handler
short-circuits. Ordering changes and the suite goes red for a reason nobody can find.

Fix: fresh fixtures per test, inside a transaction that rolls back. Then run the suite in random
order (`pytest-randomly`, `jest --randomize`) so the coupling surfaces immediately instead of
six months later.

## Timing assertions as hard gates

```python
assert elapsed < 0.05
```

A shared CI runner under load fails this. The team adds a retry, then marks it flaky, then
deletes it, and the ReDoS regression it guarded is now untested.

Fix: assert the structural property where you can — the pattern is a literal, the query has a
`LIMIT`, the recursion depth is capped. Where only timing works, use a generous bound, isolate
the job, and treat a failure as a prompt to measure. See
[troubleshooting.md](troubleshooting.md#the-test-is-flaky).

## Treating scanner output as findings

A DAST report with 40 alerts pasted into a ticket. Half are informational headers, several are
duplicates of one root cause, and two are wrong. The team's first reaction is to distrust the
whole report, which is a rational response to that input.

Fix: reproduce each candidate by hand with a request you wrote. Group by root cause. Report only
what you reproduced, and list the rest as unverified with the reason. Same discipline as code
review: no exploitation path, no finding.

## Chasing tool coverage instead of threat coverage

The suite has a test for every OWASP category because the categories are a list, so nine tests
exist and none of them match how this application is attacked. Meanwhile the multi-step checkout
flow, which is where the money is, has no abuse-case tests.

Fix: derive from abuse cases and past incidents first, then check the standard for gaps. WSTG is
a source of test procedures, not a quota.

## Fuzzing without saving the corpus

A nightly fuzz job finds a crash, prints it in a log that rotates after seven days, and the
crash is rediscovered next quarter.

Fix: commit every crashing input as a named regression test the moment it is found, and persist
the corpus between runs so coverage accumulates instead of restarting from empty each night.

## Scanning without authorization, or beyond it

An active scan configured for `*.example.com` reaches a subdomain pointing at a third-party
service. That is now someone else's system, tested without permission.

Fix: enumerate targets explicitly, never with a wildcard. Confirm every host resolves to
infrastructure in scope before the scan window, and re-confirm before each run, because DNS
changes. See [SKILL.md](SKILL.md#authorized-scope-first).

## Production data in a fixture

A "sanitized" export in `tests/fixtures/users.sql` with real email addresses, because masking the
names felt sufficient.

Fix: generate fixtures. The suite is on every laptop and in every fork, and a fixture is
published the moment it is committed. See
[best-practices.md](best-practices.md#test-data-safety).

## A green suite reported as "no vulnerabilities"

The suite covers the REST API. The GraphQL endpoint, the admin panel, the webhook consumer, and
the scheduled job are untested. The report says the application passed.

Fix: report what was tested and what was not, in the same message. A coverage statement without
its gaps is a claim you cannot support.

## Sources

- <https://owasp.org/www-project-web-security-testing-guide/v42/>
- <https://owasp.org/Top10/2025/>
- <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
