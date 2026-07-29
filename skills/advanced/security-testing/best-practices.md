# Security Testing Practices

Patterns for tests that fail on vulnerable code. Each names the WSTG v4.2 test, the ASVS
chapter, and the CWE where one applies.

Weak tests are labelled `Weak:` and pass on both the vulnerable and the fixed version. That is
the property that makes them worthless, and it is not visible from reading them alone - you
find it by running them against the unfixed code.

## Write the failing test first

`A01:2025` · ASVS V15 · WSTG-ATHZ-04

This is the highest-value habit in the file, and the one most often skipped. A regression test
written after the fix, against the fixed code, proves that the fixed code passes. It does not
prove the test would have caught the bug. Those are different claims, and only the second one
is worth anything.

The discipline is four steps, in this order:

1. Reproduce the vulnerability with a request. By hand, or with `curl`, before any test file
   exists. If you cannot make it happen once, you do not understand it yet.
2. Write the test so it fails. Run it against the unfixed code and read the failure message.
   The message must describe the vulnerability, not a missing fixture or a typo in the URL.
3. Apply the fix. Nothing else in the same commit.
4. Run the test again. It must pass for the reason you expect, and the rest of the suite must
   still pass.

Worked example. The bug: `GET /api/orders/{id}` returns any order to any authenticated user.

```bash
# Step 1: reproduce. bob reads alice's order.
$ curl -s -H "Authorization: Bearer $BOB_TOKEN" localhost:8000/api/orders/1041 | jq .customer_id
7          # alice's id. bob's is 12.
```

```python
# Step 2: the test, written and run BEFORE the fix.
# tests/regression/test_gh1284_order_bola.py
"""Regression: CWE-639 / A01:2025 / API1:2023.

Any authenticated user could read any order by ID. Fixed in #1284.
Confirmed failing on 4f9c1ab (pre-fix): returned 200 with alice's order body.
"""

def test_bob_cannot_read_alices_order(client, alice, bob, order_factory):
    order = order_factory(customer=alice, total_cents=48_00)

    resp = client.get(f"/api/orders/{order.id}", headers=bob.auth_headers)

    assert resp.status_code == 404
    assert str(order.total_cents) not in resp.text
    assert alice.email not in resp.text


def test_alice_can_still_read_her_own_order(client, alice, order_factory):
    order = order_factory(customer=alice)
    resp = client.get(f"/api/orders/{order.id}", headers=alice.auth_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == order.id
```

```text
# Step 2, continued: the run on unfixed code. This output is the evidence.
$ git stash && pytest tests/regression/test_gh1284_order_bola.py -q
FAILED test_bob_cannot_read_alices_order - assert 200 == 404
1 failed, 1 passed
```

The second test matters as much as the first. Without it, the cheapest way to make the suite
green is to break the endpoint for everyone, and a fix that returns 404 to the owner too would
ship unnoticed.

Five properties of a regression test that keeps working:

- It names the vulnerability, not the fix. `test_bob_cannot_read_alices_order` survives a
  rewrite of the authorization layer; `test_owner_filter_applied` does not.
- It records the commit it was observed failing on. That sentence in the docstring is the only
  durable proof anyone can audit later.
- It asserts absence of the data, not just the status. A 404 with the order serialized into the
  error body is still a disclosure.
- It lives in a directory nobody prunes. A `tests/regression/` tree with an issue reference per
  file is harder to delete during a cleanup than a test buried in a 900-line file.
- It goes in the same PR as the fix, and the PR description quotes the failing run.

Two situations where you cannot get a red run, and what to do instead:

- The fix is already merged and you are adding the test late. Check out the parent commit, run
  the test there, record the result, and return. If the code has moved too far, say so in the
  docstring: "not verified against the vulnerable revision; the assertion follows the reported
  reproduction in #1284." An unverified test with an honest note is worth more than one that
  implies verification it never had.
- The vulnerability needs infrastructure you do not have in CI, such as DNS rebinding. Write the
  test, mark it `@pytest.mark.skip(reason=...)` with the missing dependency named, and state the
  gap in the report. A skipped test that names its blocker is a tracked gap; a deleted one is
  not.

## Derive tests from abuse cases

`A06:2025` · ASVS V2 · WSTG-BUSL-01

A use case says what the feature does. An abuse case says what someone does to it. Write the
second one as a table before writing any test, because the test names come straight out of it.

| Use case | Abuse case | Test asserts | WSTG |
|---|---|---|---|
| User reads their invoice | Reads another user's invoice | 404, no body leak | WSTG-ATHZ-04 |
| User exports their data | Exports another tenant's data | 404 | WSTG-ATHZ-02 |
| User exports their data | Exports 500 times in a minute | 429 after the limit | WSTG-BUSL-05 |
| User uploads an avatar | Uploads a `.php` file renamed `.png` | Rejected by content, not name | WSTG-BUSL-09 |
| User sets a webhook | Points it at `169.254.169.254` | Rejected before the request | WSTG-INPV-19 |
| User resets a password | Reuses the token twice | Second attempt fails | WSTG-ATHN-09 |
| User logs out | Replays the old session cookie | 401 | WSTG-SESS-06 |
| User applies a coupon | Applies it twice concurrently | One succeeds | WSTG-BUSL-04 |

Five abuse-case classes worth walking every feature through: cross-user, cross-tenant, volume,
ordering, and replay. Payload injection is a sixth and the one people start with, which is why
the first five get missed.

## Authorization matrix testing

`A01:2025` · `API1:2023` · `CWE-639`, `CWE-862` · ASVS V8 · WSTG-ATHZ-02, WSTG-ATHZ-04

Access control is a finite grid, so test it exhaustively. Write the grid as data and let the
test framework expand it. Hand-written authorization tests cover the happy path and one denial;
generated ones cover the cells you would not have thought to write.

```python
# Strong: the matrix is data, so a new role or operation adds assertions automatically
import pytest

# actor, target owner, operation, expected status
MATRIX = [
    ("anon",        "alice", "read",   401),
    ("anon",        "alice", "update", 401),
    ("anon",        "alice", "delete", 401),
    ("alice",       "alice", "read",   200),
    ("alice",       "alice", "update", 200),
    ("alice",       "alice", "delete", 204),
    ("bob",         "alice", "read",   404),   # same tenant, not owner
    ("bob",         "alice", "update", 404),
    ("bob",         "alice", "delete", 404),
    ("carol",       "alice", "read",   404),   # other tenant
    ("carol",       "alice", "update", 404),
    ("carol",       "alice", "delete", 404),
    ("tenant_admin","alice", "read",   200),
    ("tenant_admin","alice", "update", 200),
    ("tenant_admin","alice", "delete", 204),
]

OPS = {
    "read":   lambda c, iid, h: c.get(f"/api/invoices/{iid}", headers=h),
    "update": lambda c, iid, h: c.patch(f"/api/invoices/{iid}", json={"note": "x"}, headers=h),
    "delete": lambda c, iid, h: c.delete(f"/api/invoices/{iid}", headers=h),
}

@pytest.mark.parametrize("actor,owner,op,expected", MATRIX)
def test_invoice_authorization_matrix(client, actors, invoices, actor, owner, op, expected):
    resp = OPS[op](client, invoices[owner].id, actors[actor].auth_headers)
    assert resp.status_code == expected, f"{actor} {op} on {owner}'s invoice"

    if expected in (401, 403, 404):
        assert "total_cents" not in resp.text   # denial must not leak the object
```

Four things this catches that a hand-written suite does not:

- Delete and update, which are usually authorized separately from read and often missed.
- Cross-tenant as distinct from cross-user. A tenant admin who can read across tenants is a
  different bug from one who can read across users.
- Existence disclosure. Not-yours and not-found both return 404, asserted in the same grid.
- Denial bodies that still contain the object, which happens when a serializer runs before the
  check.

Add a row asserting the nonexistent case matches the not-yours case:

```python
def test_nonexistent_and_not_yours_are_indistinguishable(client, actors, invoices):
    mine_not = client.get("/api/invoices/999999", headers=actors["bob"].auth_headers)
    not_mine = client.get(f"/api/invoices/{invoices['alice'].id}",
                          headers=actors["bob"].auth_headers)
    assert mine_not.status_code == not_mine.status_code
    assert mine_not.json() == not_mine.json()
```

Limitation worth stating: the matrix tests the endpoints you list. An unlisted route, a GraphQL
resolver, or a batch endpoint that takes an array of IDs is untested. Enumerate routes from the
router, not from memory - WSTG-INPV-19 aside, the most common miss is a second code path to the
same object.

## Assert the security property, not the status code

`A05:2025` · ASVS V1 · WSTG-INPV-01

```python
# Weak: passes on vulnerable code, because a reflected payload still returns 200
def test_search_xss():
    resp = client.get("/search", params={"q": "<script>alert(1)</script>"})
    assert resp.status_code == 200
```

The endpoint that reflects the script unescaped returns 200. So does the fixed one. The test
distinguishes nothing.

```python
# Strong: assert the payload is not present in an executable form
import html

PAYLOAD = "<script>alert(1)</script>"

def test_search_reflects_query_escaped():
    resp = client.get("/search", params={"q": PAYLOAD})
    assert resp.status_code == 200
    body = resp.text
    assert PAYLOAD not in body                      # not raw
    assert html.escape(PAYLOAD) in body             # present, but as text
    assert "<script>alert" not in body.replace(" ", "")
```

Why this works: it names both halves of the property. The payload must be absent in executable
form and present in escaped form - the second half stops the test passing because the endpoint
started dropping the parameter entirely, which is a different bug wearing the same green tick.

For attribute and JavaScript contexts, escaping alone is not the property. `"` inside an
unquoted attribute breaks out even when `<` is escaped, so the assertion must match the sink's
context. Where the sink is the DOM, use a browser test - see below.

## Test DOM XSS in a browser, not with string matching

`A05:2025` · `CWE-79` · ASVS V1, V3 · WSTG-CLNT-01

```javascript
// Weak: the payload never appears in the server response, so this always passes
test("no xss in profile", async () => {
  const res = await request(app).get("/profile?name=<img src=x onerror=alert(1)>");
  expect(res.text).not.toContain("onerror");
});
```

DOM XSS happens after the response. The sink is `innerHTML` in client JavaScript, and the
server body is innocent. A response-body assertion cannot see it.

```javascript
// Strong: a real browser, and the assertion is that script did not execute
import { test, expect } from "@playwright/test";

test("profile name does not execute injected script", async ({ page }) => {
  const dialogs: string[] = [];
  page.on("dialog", async (d) => { dialogs.push(d.message()); await d.dismiss(); });

  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));

  await page.goto("/profile?name=" + encodeURIComponent('<img src=x onerror=alert(1)>'));

  // The text must render as text, and nothing must execute.
  await expect(page.getByTestId("display-name"))
    .toHaveText('<img src=x onerror=alert(1)>');
  expect(dialogs).toEqual([]);
  expect(await page.locator("[data-testid=display-name] img").count()).toBe(0);
});
```

Why this works: it observes execution, which is the actual security property, through three
independent signals - no dialog, no injected element in the DOM, and the payload rendered as
text. Checking only for the absence of a dialog would pass against a payload that exfiltrates
without one.

Pair it with a CSP assertion, which is cheap and catches a whole class:

```javascript
test("csp is served and has no unsafe-inline for scripts", async ({ request }) => {
  const res = await request.get("/profile");
  const csp = res.headers()["content-security-policy"] ?? "";
  expect(csp).not.toBe("");
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
});
```

## Property and fuzz testing

`A05:2025` · `CWE-22`, `CWE-1333` · ASVS V5 · WSTG-ATHZ-01

Example-based tests cover the encodings you know. The interesting ones are the encodings you do
not, which is precisely what a property test explores.

```python
# Weak: three payloads, all the obvious ones
@pytest.mark.parametrize("name", ["../etc/passwd", "../../etc/passwd", "/etc/passwd"])
def test_no_traversal(name):
    with pytest.raises(NotFound):
        resolve_upload_path(name)
```

```python
# Strong: the invariant holds for every string, and Hypothesis hunts counterexamples
from hypothesis import given, strategies as st, settings, HealthCheck
from pathlib import Path

UPLOAD_DIR = Path("/srv/uploads").resolve()

# Bias the alphabet towards the characters that break path handling.
path_ish = st.text(
    alphabet=st.sampled_from(list("abc./\\%2f2e:~ \t\x00") + ["..", "%2e", "%252f"]),
    min_size=1, max_size=60,
)

@settings(max_examples=500, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(name=path_ish)
def test_resolved_upload_path_never_escapes(name):
    try:
        resolved = resolve_upload_path(name)
    except (NotFound, ValueError):
        return                       # rejecting input is an acceptable outcome
    assert Path(resolved).resolve().is_relative_to(UPLOAD_DIR)
```

Why this works: the assertion is the invariant, so it holds for inputs nobody enumerated. The
`except: return` matters - a property test must accept rejection as valid, or it fails on every
input the validator correctly refuses and tells you nothing.

Two more properties worth stating for their whole class:

```python
# Idempotence of the encoder: encoding twice must not produce a decodable payload
@given(s=st.text(max_size=200))
def test_html_encoder_output_contains_no_active_markup(s):
    out = encode_html(s)
    assert "<script" not in out.lower()
    assert not re.search(r"on\w+\s*=", out, re.I)

# Bounded work: no input makes the matcher superlinear (CWE-1333)
@given(s=st.text(alphabet="a!", min_size=1, max_size=2000))
def test_search_matcher_is_bounded(s):
    start = time.perf_counter()
    run_search_filter(s)
    assert time.perf_counter() - start < 0.25
```

Timing assertions are flaky by nature. Use a generous bound, run them on a dedicated job, and
treat a failure as a signal to measure rather than as a hard gate. The honest alternative is to
assert the structural property instead - that the pattern is a literal, not a regex - which is
deterministic.

Where a real fuzzer beats a property test: binary parsers, file format handlers, and anything
with a state machine. Atheris for Python, `jazzer` for the JVM, `cargo-fuzz` for Rust,
libFuzzer or AFL++ for C and C++. Commit every crashing input as a named regression case, since
a corpus is not a test suite.

## SSRF tests must assert the request was never sent

`A06:2025` · `CWE-918` · ASVS V2, V12 · WSTG-INPV-19

```python
# Weak: an outbound call to a private address that fails for network reasons looks like a pass
def test_no_ssrf():
    resp = client.post("/webhooks", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert resp.status_code != 200
```

In CI there is nothing at that address, so the request times out and the endpoint returns 502.
The test passes against completely unprotected code.

```python
# Strong: intercept the HTTP client and assert it was never invoked
from unittest.mock import patch

BLOCKED = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://127.0.0.1:6379/",                     # loopback service
    "http://[::1]:8080/",                          # IPv6 loopback
    "http://10.0.0.5/admin",                       # RFC1918
    "http://0177.0.0.1/",                          # octal encoding of 127.0.0.1
    "http://2130706433/",                          # decimal encoding
    "file:///etc/passwd",                          # non-HTTP scheme
    "gopher://127.0.0.1:6379/_SET%20k%20v",        # scheme smuggling
]

@pytest.mark.parametrize("url", BLOCKED)
def test_webhook_url_is_rejected_without_any_outbound_request(client, actor, url):
    with patch("app.http.session.request") as send:
        resp = client.post("/webhooks", json={"url": url}, headers=actor.auth_headers)
    assert resp.status_code == 400
    assert send.call_count == 0, f"outbound request attempted for {url}"
```

Why this works: `send.call_count == 0` is the security property. A 400 alone could come from
the request failing after it was sent, which is a blind SSRF that already reached the internal
service.

Add the redirect case, which is the one allowlists miss:

```python
def test_redirect_to_private_address_is_not_followed(client, actor, httpserver):
    httpserver.expect_request("/r").respond_with_data(
        status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
    resp = client.post("/webhooks", json={"url": httpserver.url_for("/r")},
                       headers=actor.auth_headers)
    assert resp.status_code == 400
```

Stated limitation: neither test covers DNS rebinding, where the hostname resolves to a public
address during validation and a private one during the connection. Detecting that needs a DNS
server under test control that returns different answers on successive queries. If you have not
built that, say the case is untested rather than implying SSRF is covered.

## File upload tests must use real file bytes

`A08:2025` · `CWE-434` · ASVS V5 · WSTG-BUSL-08, WSTG-BUSL-09

```python
# Weak: the declared content type is the only thing being tested
def test_upload_rejects_php():
    resp = client.post("/avatar", files={"f": ("x.php", b"<?php ?>", "application/x-php")})
    assert resp.status_code == 400
```

This passes on code that checks only `content_type`, which is the vulnerability. The attacker
sends `image/png` and the test never tries that.

```python
# Strong: real magic bytes, mismatched names, and the stored artefact is inspected
PNG = bytes.fromhex("89504e470d0a1a0a") + b"\x00" * 64
GIF_POLYGLOT = b"GIF89a" + b"<?php system($_GET['c']); ?>"

CASES = [
    # (filename, bytes, declared type, expected)
    ("shell.php",     b"<?php ?>",   "image/png",   400),   # png claimed, php bytes
    ("shell.php.png", b"<?php ?>",   "image/png",   400),   # double extension
    ("ok.png",        PNG,           "image/png",   201),
    ("ok.png",        GIF_POLYGLOT,  "image/png",   400),   # polyglot
    ("../../evil.png",PNG,           "image/png",   400),   # traversal in the name
    ("big.png",       PNG + b"\x00" * (11 * 1024 * 1024), "image/png", 413),
]

@pytest.mark.parametrize("name,data,ctype,expected", CASES)
def test_avatar_upload(client, actor, tmp_storage, name, data, ctype, expected):
    resp = client.post("/avatar", files={"f": (name, data, ctype)},
                       headers=actor.auth_headers)
    assert resp.status_code == expected

    if expected != 201:
        assert list(tmp_storage.iterdir()) == []       # nothing persisted on rejection

def test_stored_avatar_name_is_server_generated(client, actor, tmp_storage):
    client.post("/avatar", files={"f": ("user-chosen.png", PNG, "image/png")},
                headers=actor.auth_headers)
    stored = list(tmp_storage.iterdir())
    assert len(stored) == 1
    assert "user-chosen" not in stored[0].name
    assert stored[0].suffix == ".png"
```

Why this works: the bytes decide, the filename is asserted to be discarded, and the rejection
path is checked for side effects. A rejection that still wrote the file to a temporary directory
inside the web root is a bypass, and only the storage assertion sees it.

The polyglot case is the honest one to keep failing if your control is magic-number detection
alone. Re-encoding an image through a library is the stronger control; if you have not done
that, the test documents the gap.

## Injection tests: assert behaviour, not error text

`A05:2025` · `CWE-89` · ASVS V1 · WSTG-INPV-05

```python
# Weak: asserts an error message, which the ORM changes in a minor version
def test_sqli():
    resp = client.get("/invoices", params={"sort": "id; DROP TABLE users--"})
    assert "syntax error" in resp.text.lower()
```

Two problems. It asserts on an error string, which is brittle, and a syntax error means the
input reached the SQL parser - the payload got through and merely failed. That is a vulnerable
endpoint producing a green test.

```python
# Strong: assert rejection at the boundary, and assert the database is untouched
BAD_SORTS = [
    "id; DROP TABLE users--",
    "(SELECT 1)",
    "id/**/ASC",
    "total_cents, (CASE WHEN (1=1) THEN 1 ELSE 2 END)",
    "id ASC; SELECT pg_sleep(5)",
]

@pytest.mark.parametrize("sort", BAD_SORTS)
def test_sort_parameter_rejected_at_boundary(client, actor, db, sort):
    before = db.scalar("SELECT count(*) FROM users")
    resp = client.get("/invoices", params={"sort": sort}, headers=actor.auth_headers)
    assert resp.status_code == 400
    assert "syntax" not in resp.text.lower()     # no engine detail leaks to the client
    assert db.scalar("SELECT count(*) FROM users") == before

def test_sort_allowlist_accepts_known_keys(client, actor):
    for key in ("created", "total", "status"):
        assert client.get("/invoices", params={"sort": key},
                          headers=actor.auth_headers).status_code == 200
```

Why this works: 400 proves the allowlist rejected the value before SQL was built, the absence
of engine detail covers WSTG-ERRH-01 at the same time, and the positive test stops the fix from
being "reject everything". Blind injection deserves its own case - a timing payload that
returns 200 in 5 seconds is a passing test on the weak version above.

## Race conditions need concurrency, not sequence

`A06:2025` · `CWE-362`, `CWE-367` · ASVS V2 · WSTG-BUSL-04

A check-then-act flaw does not reproduce sequentially. Two requests in a row leave the balance
correct; two requests in flight at the same time do not.

```typescript
// Weak: sequential, so the second call sees the first one's committed result
it("cannot overdraw", async () => {
  await request(app).post("/transfer").send({ to: "bob", cents: 8000 }).set(auth);
  const second = await request(app).post("/transfer").send({ to: "bob", cents: 8000 }).set(auth);
  expect(second.status).toBe(400);
});
```

That passes against code with no locking at all. The vulnerability lives in the window between
reading the balance and writing it, and sequential requests never open the window.

```typescript
// Strong: fire concurrently, then assert the invariant on the persisted state
import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { app } from "../src/app";
import { db, resetDb, seedAccount } from "./helpers";

describe("balance transfer concurrency (CWE-362)", () => {
  beforeEach(async () => {
    await resetDb();
    await seedAccount({ id: "alice", cents: 10_000 });
    await seedAccount({ id: "bob", cents: 0 });
  });

  it("cannot be overdrawn by concurrent transfers", async () => {
    const auth = { Authorization: "Bearer alice-test-token" };
    const N = 20;

    const results = await Promise.all(
      Array.from({ length: N }, () =>
        request(app).post("/api/transfers")
          .set(auth)
          .send({ to: "bob", cents: 8_000, idempotencyKey: crypto.randomUUID() })
          .then((r) => r.status)
          .catch(() => 0),
      ),
    );

    const accepted = results.filter((s) => s === 201).length;
    const alice = await db.account("alice");
    const bob = await db.account("bob");

    // The invariant, not the count: money is conserved and nothing goes negative.
    expect(alice.cents).toBeGreaterThanOrEqual(0);
    expect(alice.cents + bob.cents).toBe(10_000);
    expect(accepted).toBe(1);              // only one 8000 transfer fits in 10000
  });
});
```

Why this works: the assertion is a conservation invariant plus a non-negativity bound, which
holds regardless of scheduling. Asserting only `accepted === 1` would be flaky in the other
direction - under a slow runner the requests may serialize by accident and pass on broken code.
Checking the persisted totals catches the double-spend even when the status codes look sane.

Three notes on making this test honest rather than decorative:

- Run it against a real database with the production isolation level. An in-memory stub with a
  single-threaded driver serializes everything and the test can never fail.
- Repeat it. A race reproduces probabilistically; `N = 20` with the loop run a few times is more
  reliable than one attempt at `N = 2`. If it passes once it is not evidence.
- Prefer a deterministic version where the code allows it: a test that holds a transaction open,
  or one that patches the balance read to block on a barrier, fails every time. Probabilistic
  tests belong in CI only alongside the structural assertion - that the update uses
  `SELECT ... FOR UPDATE`, a conditional `UPDATE ... WHERE cents >= ?`, or a unique constraint.

The same pattern applies to coupon redemption, invitation acceptance, stock decrement, and any
"first one wins" flow. WSTG-BUSL-05 covers the use-count limit case.

## Replay tests: the same request twice must not work twice

`A08:2025` · `CWE-294`, `CWE-384` · ASVS V7, V9 · WSTG-SESS-06, WSTG-ATHN-09

Signature verification proves a message came from the sender. It does not prove the message is
new. A captured webhook replayed an hour later verifies perfectly.

```typescript
// Weak: only checks that a bad signature is rejected
it("rejects a forged webhook", async () => {
  const res = await request(app).post("/webhooks/payments")
    .set("X-Signature", "sha256=deadbeef")
    .send({ event: "payment.succeeded", amount: 5000 });
  expect(res.status).toBe(401);
});
```

Signature checking is the part most implementations get right. Replay is the part they miss, and
this test says nothing about it.

```typescript
// Strong: a valid, correctly signed request, sent twice
import crypto from "node:crypto";

const SECRET = "test-webhook-secret-not-a-real-key";

function sign(body: string, timestamp: number) {
  return "sha256=" + crypto.createHmac("sha256", SECRET)
    .update(`${timestamp}.${body}`).digest("hex");
}

function post(body: string, timestamp: number) {
  return request(app).post("/webhooks/payments")
    .set("X-Timestamp", String(timestamp))
    .set("X-Signature", sign(body, timestamp))
    .set("Content-Type", "application/json")
    .send(body);
}

it("processes a signed webhook exactly once", async () => {
  const body = JSON.stringify({ id: "evt_1", event: "payment.succeeded", amount: 5000 });
  const ts = Math.floor(Date.now() / 1000);

  const first = await post(body, ts);
  expect(first.status).toBe(200);

  const replay = await post(body, ts);          // byte-identical, still valid signature
  expect(replay.status).toBe(409);

  // The invariant: one credit, not two.
  expect(await db.creditsFor("evt_1")).toHaveLength(1);
  expect((await db.account("merchant")).cents).toBe(5000);
});

it("rejects a signed webhook outside the freshness window", async () => {
  const body = JSON.stringify({ id: "evt_2", event: "payment.succeeded", amount: 5000 });
  const old = Math.floor(Date.now() / 1000) - 60 * 60;      // one hour ago
  const res = await post(body, old);
  expect(res.status).toBe(400);
  expect(await db.creditsFor("evt_2")).toHaveLength(0);
});
```

Why this works: the replay carries a genuine signature, so it isolates freshness from
authenticity. The side-effect assertion is what proves it - a handler that returns 409 after
already crediting the account passes a status-only test.

The equivalent cases elsewhere, all the same shape:

| Surface | Replay to test | Expected |
|---|---|---|
| Password reset link | Use the token twice | Second use fails |
| Session cookie | Send it after logout | 401 (WSTG-SESS-06) |
| Session cookie | Send it after a password change | 401 |
| OTP / MFA code | Submit the same code twice | Second submission fails |
| Payment intent | Confirm the same intent twice | One charge |
| JWT after revocation | Present a token from the revocation list | 401 |

For the logout case, capture the cookie, log out, then reuse it. Testing that logout returns 200
tests nothing - the question is whether the old token is dead server-side, which only the reuse
attempt answers.

## Partial failure must not leave a usable half-state

`A10:2025` · `CWE-459` · ASVS V16 · WSTG-ERRH-01

Abuse-case testing includes making the dependency fail. The interesting question is what
persisted when step three of four threw.

```python
# Strong: force the failure, then assert nothing exploitable survived
def test_failed_notification_does_not_leave_an_active_api_key(client, actor, db):
    with patch("app.notify.send_email", side_effect=SMTPError("down")):
        resp = client.post("/api/keys", json={"label": "ci"}, headers=actor.auth_headers)

    assert resp.status_code in (201, 500)

    keys = db.query(ApiKey).filter_by(owner_id=actor.id).all()
    if resp.status_code == 500:
        # Rolled back: no key exists, so none was returned to a client that never saw it.
        assert keys == []
    else:
        # Committed deliberately: the key must be usable and auditable, not orphaned.
        assert len(keys) == 1 and keys[0].revoked_at is None
        assert db.query(AuditLog).filter_by(action="api_key.created").count() == 1
```

Why this works: it accepts either design and rejects the third outcome, which is the bug - a key
row created, no audit entry, and a 500 to the caller, so a live credential exists that nobody
owns. Testing only that the endpoint returns 500 misses it entirely.

## Coverage does not measure security

`A06:2025` · ASVS V15

Line and branch coverage measure how much of the code the suite executed. Security testing is
about the requests the code does not handle, so the metric points away from the work.

Three concrete ways high coverage coexists with an exploitable application:

- The vulnerable line is fully covered. `db.query(Order).get(order_id)` runs in every happy-path
  test. 100% line coverage on a missing authorization check.
- The missing code has no coverage to measure. There is no line for the ownership filter that
  was never written, no branch for the tenant check that does not exist. Coverage cannot report
  the absence of a control.
- Coverage counts execution, not assertion. A test that calls the endpoint and asserts
  `status_code == 200` covers every line in the handler and verifies nothing about it.

What to track instead, all of it checkable:

| Metric | Question it answers |
|---|---|
| Abuse-case coverage | Of the abuse cases listed for this feature, how many have a test? |
| Authorization matrix completeness | Which cells of roles x operations are asserted? |
| Regression coverage of past findings | How many closed vulnerabilities have a test that was seen failing? |
| WSTG applicability coverage | Of the WSTG v4.2 tests that apply to this application, which are automated, manual, or unaddressed? |
| Mutation score on security-critical modules | Would the suite notice if the authorization check were removed? |

Mutation testing is the closest available proxy for "would this suite catch a regression".
Removing a conditional is exactly the mutation an authorization bug is, so a surviving mutant in
an authorization module is a real gap. Run it on the security-critical modules only -
`mutmut`, `cosmic-ray`, or Stryker for TypeScript - because a whole-codebase mutation run costs
more than it returns.

Use coverage for one thing only: finding files the suite never touches at all. A handler with
zero coverage has no tests, which is worth knowing. Beyond that, a coverage target is a number
someone will hit with assertion-free tests.

## Test data safety

`A04:2025` · ASVS V14 · WSTG-CONF-04

A test suite is copied to every developer laptop, every CI runner, and every fork. Anything in
a fixture is effectively published.

- No production data. Not a sanitized export, not "just the schema plus a few rows". A masked
  dataset is a compliance artefact requiring its own review; generated data is cheaper and
  safer.
- No real credentials, including expired or revoked ones. They demonstrate that real ones live
  somewhere reachable, and revocation is often incomplete.
- Placeholder identities only: `alice`, `bob`, `carol`, `example.com`, `attacker.example`.
  `example.com`, `example.org`, and `example.net` are reserved for documentation; a
  `.test`-suffixed name is safe for local resolution.
- Generate PII rather than copying it. A factory that produces syntactically valid, semantically
  meaningless records is reproducible and carries no retention obligation.
- Payload fixtures stay inert. Use the EICAR test string for antivirus paths rather than real
  malware, and keep archive-bomb fixtures small and clearly named.
- Scrub artefacts. HAR files, screenshots, and DAST reports contain session cookies and
  sometimes response bodies with real data when a scan ran against staging with a production
  replica.
- Seed deterministically, and print the seed on failure. A fixture that depends on the current
  date fails once a year for reasons nobody can reproduce.

```python
# Strong: fixtures are generated, deterministic, and obviously fake
import factory

class UserFactory(factory.Factory):
    class Meta:
        model = User

    email = factory.Sequence(lambda n: f"user{n}@example.com")
    display_name = factory.Sequence(lambda n: f"Test User {n}")
    password_hash = factory.LazyFunction(lambda: hash_password("not-a-real-password"))
    tenant_id = 1
```

## CI execution

`A03:2025`, `A09:2025` · ASVS V13, V15

Security tests belong in the same job as the rest of the suite, so they cannot be skipped
separately. Scanners belong in their own jobs, so a scanner outage does not block a hotfix.

```yaml
# .github/workflows/security.yml
name: security
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 3 * * *"          # nightly: long fuzz and full dependency audit

permissions:
  contents: read                  # least privilege; raise per-job where needed

jobs:
  tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements-dev.txt
      # Security tests are part of the suite. No separate marker to forget.
      - run: pytest -q --strict-markers

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # history, not just the diff
      - run: gitleaks detect --redact --no-banner --exit-code 1

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Diff-scoped on PRs keeps the signal high; full scan runs nightly.
      - run: semgrep ci --config p/security-audit --error

  fuzz-short:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements-dev.txt
      # Bounded so a PR cannot hang. The nightly job runs unbounded.
      - run: pytest tests/property -q -p no:randomly
        env:
          HYPOTHESIS_PROFILE: ci

  dast-baseline:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose -f docker-compose.ci.yml up -d --wait
      # Baseline mode is passive. Active scanning goes in the scheduled job.
      - run: |
          docker run --rm --network host \
            -v "$PWD:/zap/wrk:rw" \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py -t http://localhost:8080 \
              -c .zap/rules.tsv -r zap-report.html
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: zap-report.html
```

Decisions in that file worth copying:

- Deterministic checks gate; probabilistic ones report. Unit and integration tests block on
  every push. The nightly fuzz and full active scan file issues instead.
- `fetch-depth: 0` for secret scanning. Scanning only the diff misses the secret committed
  three months ago and never rotated.
- A committed baseline (`.zap/rules.tsv`) so a scan reports new findings rather than the same
  forty informational alerts every run. Without a baseline the gate is noise and gets removed.
- Bounded property-test budget on PRs. An unbounded run makes the pipeline duration random,
  which is how the job gets marked `continue-on-error` and then ignored.
- Least-privilege token at the workflow level, raised per job only where a job needs to write.
- Scan credentials from the CI secret store. A DAST run against staging needs a real login; put
  it in secrets, scope the account to staging, and rotate it on a schedule.

Failing honestly matters more than passing. If a scanner cannot run, the job fails and says so;
`|| true` on a security step converts a control into decoration.

## Sources

- <https://owasp.org/www-project-web-security-testing-guide/v42/>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- <https://cheatsheetseries.owasp.org/>
