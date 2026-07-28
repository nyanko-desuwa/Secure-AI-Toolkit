# Security Testing Examples

Eight pairs. In each one the weak test passes against the vulnerable code, and the strong test
fails against it. That difference is the only thing that makes a security test worth its
runtime.

Every pair names the WSTG v4.2 test ID, the CWE, the OWASP Top 10 2025 category, and the ASVS
5.0 chapter. Where a control has a known gap, the gap is stated rather than implied away.

## Contents

- [1. BOLA on an order endpoint](#1-bola-on-an-order-endpoint) — WSTG-ATHZ-04, CWE-639
- [2. Privilege escalation through a writable role field](#2-privilege-escalation-through-a-writable-role-field) — WSTG-ATHZ-03, CWE-915
- [3. Stored XSS in a comment body](#3-stored-xss-in-a-comment-body) — WSTG-INPV-02, CWE-79
- [4. Blind SQL injection in a filter parameter](#4-blind-sql-injection-in-a-filter-parameter) — WSTG-INPV-05, CWE-89
- [5. SSRF in a webhook registration](#5-ssrf-in-a-webhook-registration) — WSTG-INPV-19, CWE-918
- [6. Malicious file upload](#6-malicious-file-upload) — WSTG-BUSL-09, CWE-434
- [7. Session surviving logout](#7-session-surviving-logout) — WSTG-SESS-06, CWE-613
- [8. Account enumeration on password reset](#8-account-enumeration-on-password-reset) — WSTG-IDNT-04, CWE-204

---

## 1. BOLA on an order endpoint

`A01:2025` · `API1:2023` · `CWE-639` · ASVS V8 · WSTG-ATHZ-04

The vulnerable handler authenticates and then fetches by ID alone.

```python
# Vulnerable: requireAuth answers who, nothing answers whether
@router.get("/api/orders/{order_id}")
def get_order(order_id: int, actor: User = Depends(current_user)):
    return db.query(Order).get(order_id)
```

```python
# Weak: passes on the code above. The order exists, so the status is 200 either way.
def test_get_order(client, alice, orders):
    resp = client.get(f"/api/orders/{orders['alice'].id}", headers=alice.auth_headers)
    assert resp.status_code == 200
```

The weak test only ever asks for the actor's own object, so the missing filter never shows.

```python
# Strong: another user's object, and the assertion covers the body as well as the status
def test_order_of_another_user_is_not_readable(client, alice, bob, orders):
    target = orders["bob"]

    resp = client.get(f"/api/orders/{target.id}", headers=alice.auth_headers)

    assert resp.status_code == 404          # not 403: no existence disclosure
    body = resp.text
    assert str(target.total_cents) not in body
    assert target.shipping_postcode not in body
    assert "bob@example.com" not in body


def test_own_order_is_still_readable(client, alice, orders):
    resp = client.get(f"/api/orders/{orders['alice'].id}", headers=alice.auth_headers)
    assert resp.status_code == 200
```

Why the strong version detects it: the request is the attacker's request, and the assertions
name the data that must not appear. A status-only assertion passes against a handler that
returns 404 with the order serialized into the error envelope, which happens whenever the
serializer runs before the check.

The second test is not padding. A fix that returns 404 to everyone satisfies the first test
alone, and that fix gets written during an incident.

Fixed code, for reference:

```python
@router.get("/api/orders/{order_id}")
def get_order(order_id: int, actor: User = Depends(current_user)):
    order = (db.query(Order)
               .filter(Order.id == order_id, Order.customer_id == actor.id)
               .one_or_none())
    if order is None:
        raise HTTPException(404)
    return order
```

Gap to state: this pair covers one route. The same object is often reachable through
`/api/orders/{id}/invoice`, a batch endpoint, or a GraphQL resolver. Enumerate routes from the
router and parameterize over all of them.

---

## 2. Privilege escalation through a writable role field

`A01:2025` · `API3:2023` · `CWE-915` · ASVS V2, V8 · WSTG-ATHZ-03

```javascript
// Vulnerable: the whole body is assigned, so role is client-writable
app.patch("/api/users/me", requireAuth, async (req, res) => {
  const user = await db.user.update({ where: { id: req.user.id }, data: req.body });
  res.json(user);
});
```

```javascript
// Weak: only sends the fields the UI sends, so the extra column is never exercised
it("updates the display name", async () => {
  const res = await request(app).patch("/api/users/me")
    .set(aliceAuth).send({ displayName: "Alice A." });
  expect(res.status).toBe(200);
});
```

```javascript
// Strong: send the fields the UI never sends, and assert the stored record
const PRIVILEGED_FIELDS = [
  { role: "admin" },
  { isAdmin: true },
  { tenantId: "globex" },
  { emailVerified: true },
  { creditCents: 1_000_000 },
  { id: "some-other-user-id" },
];

describe("profile update rejects privileged fields (CWE-915)", () => {
  it.each(PRIVILEGED_FIELDS)("ignores or rejects %j", async (payload) => {
    const before = await db.user.findUnique({ where: { id: alice.id } });

    const res = await request(app).patch("/api/users/me")
      .set(aliceAuth)
      .send({ displayName: "Alice A.", ...payload });

    // Either shape is acceptable: reject the request, or accept and drop the field.
    expect([200, 400, 422]).toContain(res.status);

    const after = await db.user.findUnique({ where: { id: alice.id } });
    for (const key of Object.keys(payload)) {
      expect(after[key]).toStrictEqual(before[key]);   // the property: unchanged
    }
    expect(after.id).toBe(before.id);
  });
});
```

Why the strong version detects it: the assertion is on the persisted row, not the response.
An endpoint that writes `role: "admin"` and then returns a serializer that omits `role` passes
any response-body assertion while the escalation has already happened.

Fixed code: parse into an explicit allowlist before it reaches the ORM.

```javascript
const ProfilePatch = z.object({
  displayName: z.string().min(1).max(64).optional(),
  locale: z.enum(["en", "vi"]).optional(),
}).strict();

app.patch("/api/users/me", requireAuth, async (req, res) => {
  const parsed = ProfilePatch.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_request" });
  const user = await db.user.update({ where: { id: req.user.id }, data: parsed.data });
  res.json({ id: user.id, displayName: user.displayName, locale: user.locale });
});
```

`.strict()` is the part under test. Without it the schema validates the known fields and passes
the unknown ones straight through, which is the same vulnerability with a validation library
in front of it.

---

## 3. Stored XSS in a comment body

`A05:2025` · `CWE-79` · ASVS V1, V3 · WSTG-INPV-02, WSTG-CLNT-01

Stored XSS has two halves: what the write endpoint accepts, and what the read path renders. A
test on only the first half misses the sink.

```javascript
// Weak: asserts the write was rejected, which the fixed design does not do either.
// It also never loads the page where the payload renders.
it("blocks script tags in comments", async () => {
  const res = await request(app).post("/api/posts/1/comments")
    .set(aliceAuth).send({ body: "<script>alert(1)</script>" });
  expect(res.status).toBe(400);
});
```

Storing the raw characters is fine. Escaping at render time is the control, so a test demanding
a 400 on write fails against correct code and passes against a sanitize-on-write implementation
that misses one encoding. Wrong property, wrong layer.

```javascript
// Strong: store the payload, then observe the rendered page in a real browser
import { test, expect } from "@playwright/test";

const PAYLOAD = `<img src=x onerror="window.__xss=1">`;

test("a stored comment renders as text and does not execute", async ({ page, request }) => {
  const created = await request.post("/api/posts/1/comments", {
    headers: { Authorization: `Bearer ${ALICE_TOKEN}` },
    data: { body: PAYLOAD },
  });
  expect(created.ok()).toBeTruthy();

  const dialogs: string[] = [];
  page.on("dialog", async (d) => { dialogs.push(d.message()); await d.dismiss(); });

  await page.goto("/posts/1");

  // 1. The payload is visible as text, so the feature still works.
  await expect(page.getByTestId("comment-body").last()).toHaveText(PAYLOAD);
  // 2. No element was created from it.
  expect(await page.locator('[data-testid="comment-body"] img').count()).toBe(0);
  // 3. No script ran.
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
  expect(dialogs).toEqual([]);
});

test("csp on the post page has no unsafe-inline for scripts", async ({ request }) => {
  const res = await request.get("/posts/1");
  const csp = res.headers()["content-security-policy"] ?? "";
  expect(csp).not.toBe("");
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
});
```

Why the strong version detects it: three independent signals for the same property — rendered
as text, no injected node, no side effect on `window`. The `onerror` payload is used instead of
`alert(1)` deliberately, because a dialog-only assertion misses payloads that exfiltrate
silently.

Gap to state: this covers the HTML page. If the same comment is rendered in an email, a PDF
export, or a native mobile client, each sink needs its own assertion. Escaping is per sink.

---

## 4. Blind SQL injection in a filter parameter

`A05:2025` · `CWE-89` · ASVS V1 · WSTG-INPV-05

```python
# Vulnerable: the value is parameterized, the identifier is not
def list_invoices(actor_id: int, sort: str):
    sql = f"SELECT id, total_cents FROM invoices WHERE user_id = %s ORDER BY {sort}"
    return db.execute(sql, (actor_id,)).fetchall()
```

```python
# Weak: asserts on an error string. Two ways this misleads.
def test_sqli_blocked(client, actor):
    resp = client.get("/invoices", params={"sort": "id; DROP TABLE users--"},
                      headers=actor.auth_headers)
    assert "syntax error" in resp.text.lower()
```

A syntax error means the payload reached the SQL parser: the endpoint is injectable and the
test is green. It also breaks on a driver upgrade that rewords the message, so it gets deleted
for flakiness rather than fixed.

```python
# Strong: rejection at the boundary, no engine detail, and the database is untouched
BAD_SORTS = [
    "id; DROP TABLE users--",
    "(SELECT 1)",
    "id/**/ASC",
    "total_cents, (CASE WHEN (1=1) THEN 1 ELSE 2 END)",
    "id ASC; SELECT pg_sleep(5)",
]

@pytest.mark.parametrize("sort", BAD_SORTS)
def test_sort_is_rejected_before_sql_is_built(client, actor, db, sort):
    before = db.scalar("SELECT count(*) FROM users")

    resp = client.get("/invoices", params={"sort": sort}, headers=actor.auth_headers)

    assert resp.status_code == 400
    assert "syntax" not in resp.text.lower()          # WSTG-ERRH-01 at the same time
    assert "invoices" not in resp.text                # no schema names leak
    assert db.scalar("SELECT count(*) FROM users") == before


def test_known_sort_keys_still_work(client, actor):
    for key in ("created", "total", "status"):
        resp = client.get("/invoices", params={"sort": key}, headers=actor.auth_headers)
        assert resp.status_code == 200


def test_boolean_oracle_does_not_change_result_order(client, actor):
    """Blind injection: a true and a false condition must be indistinguishable."""
    true_case = client.get("/invoices", params={"sort": "id AND 1=1"},
                           headers=actor.auth_headers)
    false_case = client.get("/invoices", params={"sort": "id AND 1=2"},
                            headers=actor.auth_headers)
    assert true_case.status_code == false_case.status_code == 400
    assert true_case.json() == false_case.json()
```

Why the strong version detects it: 400 proves the allowlist rejected the value before any SQL
was assembled, and the row count proves nothing executed. The boolean-oracle test is the one
that catches the blind case, where a naive filter strips semicolons and the injection continues
without them.

Fixed code: map input to a server-chosen identifier.

```python
SORT_COLUMNS = {"created": "created_at", "total": "total_cents", "status": "status"}

def list_invoices(actor_id: int, sort: str):
    column = SORT_COLUMNS.get(sort)
    if column is None:
        raise BadRequest("invalid_sort")
    sql = f"SELECT id, total_cents FROM invoices WHERE user_id = %s ORDER BY {column}"
    return db.execute(sql, (actor_id,)).fetchall()
```

Escaping `sort`, or filtering it with a regex, means enumerating every dangerous construction.
The allowlist enumerates the three safe ones.

---

## 5. SSRF in a webhook registration

`A06:2025` · `API7:2023` · `CWE-918` · ASVS V2, V12 · WSTG-INPV-19

```python
# Weak: in CI nothing answers on that address, so the request times out and the
# endpoint returns 502. The test passes against entirely unprotected code.
def test_no_ssrf(client, actor):
    resp = client.post("/api/webhooks", json={"url": "http://169.254.169.254/latest/meta-data/"},
                       headers=actor.auth_headers)
    assert resp.status_code != 200
```

```python
# Strong: the property is that no outbound request was attempted at all
from unittest.mock import patch

BLOCKED_URLS = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://metadata.google.internal/",           # metadata by name
    "http://127.0.0.1:6379/",                     # loopback service
    "http://[::1]:8080/",                         # IPv6 loopback
    "http://10.0.0.5/admin",                      # RFC 1918
    "http://0177.0.0.1/",                         # octal form of 127.0.0.1
    "http://2130706433/",                         # decimal form of 127.0.0.1
    "file:///etc/passwd",                         # non-HTTP scheme
    "gopher://127.0.0.1:6379/_SET%20k%20v",       # scheme smuggling
]

@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_webhook_url_rejected_with_no_outbound_request(client, actor, url):
    with patch("app.http.session.request") as send:
        resp = client.post("/api/webhooks", json={"url": url}, headers=actor.auth_headers)

    assert resp.status_code == 400
    assert send.call_count == 0, f"outbound request attempted for {url}"


def test_redirect_to_a_private_address_is_not_followed(client, actor, httpserver):
    httpserver.expect_request("/r").respond_with_data(
        status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    resp = client.post("/api/webhooks", json={"url": httpserver.url_for("/r")},
                       headers=actor.auth_headers)
    assert resp.status_code == 400


def test_a_public_url_is_still_accepted(client, actor, httpserver):
    httpserver.expect_request("/hook").respond_with_data("ok")
    resp = client.post("/api/webhooks", json={"url": httpserver.url_for("/hook")},
                       headers=actor.auth_headers)
    assert resp.status_code == 201
```

Why the strong version detects it: `send.call_count == 0` is the security property. A 400 on
its own can mean the request was sent, reached the internal service, and then failed to parse —
blind SSRF, already exploited, test green. The numeric-encoding cases are included because a
hostname denylist of `169.254.169.254` and `localhost` passes all of them.

Gaps to state, both real:

- DNS rebinding is untested. The hostname resolves to a public address during validation and a
  private one at connection time. Covering it needs a DNS server under test control that
  returns different answers on successive queries. An egress proxy with an allowlist is the
  production answer; say the case is untested rather than implying SSRF is closed.
- Mocking `app.http.session.request` couples the test to the client module path. If the
  application acquires a second HTTP client, this test does not see it. Assert on a single
  shared session object and enforce that with a lint rule or an architecture test.

---

## 6. Malicious file upload

`A08:2025` · `CWE-434` · ASVS V5 · WSTG-BUSL-08, WSTG-BUSL-09

```python
# Weak: sends a PHP file with a PHP content type, which is the one case a
# content-type check already catches. The bypass is never attempted.
def test_upload_rejects_php(client, actor):
    resp = client.post("/api/avatar",
                       files={"f": ("shell.php", b"<?php ?>", "application/x-php")},
                       headers=actor.auth_headers)
    assert resp.status_code == 400
```

```python
# Strong: real bytes, mismatched declarations, and the stored artefact is inspected
PNG = bytes.fromhex("89504e470d0a1a0a") + b"\x00" * 64
GIF_POLYGLOT = b"GIF89a" + b"<?php system($_GET['c']); ?>"
SVG_SCRIPT = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'

CASES = [
    # filename, bytes, declared type, expected status
    ("shell.php",      b"<?php ?>",  "image/png", 400),   # png claimed, php bytes
    ("shell.php.png",  b"<?php ?>",  "image/png", 400),   # double extension
    ("shell.pHp",      b"<?php ?>",  "image/png", 400),   # case variant
    ("ok.png",         PNG,          "image/png", 201),   # the happy path
    ("ok.png",         GIF_POLYGLOT, "image/png", 400),   # polyglot
    ("x.svg",          SVG_SCRIPT,   "image/svg+xml", 400),  # scriptable image format
    ("../../evil.png", PNG,          "image/png", 400),   # traversal in the name
    ("big.png", PNG + b"\x00" * (11 * 1024 * 1024), "image/png", 413),
]

@pytest.mark.parametrize("name,data,ctype,expected", CASES)
def test_avatar_upload(client, actor, storage_dir, name, data, ctype, expected):
    resp = client.post("/api/avatar", files={"f": (name, data, ctype)},
                       headers=actor.auth_headers)
    assert resp.status_code == expected

    if expected != 201:
        # Rejection must leave nothing behind, including in a temp directory.
        assert list(storage_dir.rglob("*")) == []


def test_stored_name_is_server_generated(client, actor, storage_dir):
    client.post("/api/avatar", files={"f": ("user-chosen.png", PNG, "image/png")},
                headers=actor.auth_headers)
    stored = [p for p in storage_dir.rglob("*") if p.is_file()]
    assert len(stored) == 1
    assert "user-chosen" not in stored[0].name
    assert stored[0].suffix == ".png"


def test_avatar_is_served_with_a_fixed_content_type(client, actor):
    upload = client.post("/api/avatar", files={"f": ("a.png", PNG, "image/png")},
                         headers=actor.auth_headers)
    resp = client.get(upload.json()["url"])
    assert resp.headers["content-type"] == "image/png"
    assert resp.headers.get("content-disposition", "").startswith("attachment") or \
           resp.headers.get("x-content-type-options") == "nosniff"
```

Why the strong version detects it: the bytes decide the outcome, the filename is asserted to be
discarded, the rejection path is checked for side effects, and the serving path is checked for
the header that stops a browser interpreting the file as something else. A rejection that still
wrote the upload into a temporary directory inside the web root is a bypass, and only the
storage assertion sees it.

Gap to state: magic-number detection is fooled by polyglots. The `GIF_POLYGLOT` case is left in
deliberately — if your control is magic numbers alone it fails, and that failure is accurate.
Re-encoding the image through an imaging library is the stronger control. SVG is excluded rather
than sanitized here, because sanitizing SVG safely is a project of its own.

---

## 7. Session surviving logout

`A07:2025` · `CWE-613` · ASVS V7 · WSTG-SESS-06

```javascript
// Weak: asserts that logout returns 200, which the vulnerable version also does
it("logs out", async () => {
  const res = await request(app).post("/api/logout").set(aliceAuth);
  expect(res.status).toBe(204);
});
```

Logout succeeding says nothing about whether the old credential still works. Clearing the
cookie client-side is the common vulnerable implementation, and it returns 204.

```javascript
// Strong: capture the credential, log out, then reuse it
describe("session invalidation (CWE-613)", () => {
  async function login() {
    const res = await request(app).post("/api/login")
      .send({ email: "alice@example.com", password: "correct-horse-test" });
    expect(res.status).toBe(200);
    return {
      cookie: res.headers["set-cookie"],
      token: res.body.accessToken,
      refresh: res.body.refreshToken,
    };
  }

  it("kills the session on logout", async () => {
    const s = await login();

    // Proof the credential worked before logout, or a broken fixture reads as a pass.
    expect((await request(app).get("/api/me").set("Cookie", s.cookie)).status).toBe(200);

    await request(app).post("/api/logout").set("Cookie", s.cookie).expect(204);

    expect((await request(app).get("/api/me").set("Cookie", s.cookie)).status).toBe(401);
    // The refresh token is the one people forget.
    const refreshed = await request(app).post("/api/refresh").send({ refresh: s.refresh });
    expect(refreshed.status).toBe(401);
  });

  it("kills other sessions on password change", async () => {
    const first = await login();
    const second = await login();

    await request(app).post("/api/password")
      .set("Cookie", second.cookie)
      .send({ current: "correct-horse-test", next: "new-test-passphrase-1" })
      .expect(204);

    expect((await request(app).get("/api/me").set("Cookie", first.cookie)).status).toBe(401);
  });

  it("rotates the session identifier on login", async () => {
    const anon = await request(app).get("/api/csrf");          // establishes a session
    const pre = anon.headers["set-cookie"]?.join(";") ?? "";
    const s = await login();
    expect(s.cookie.join(";")).not.toBe(pre);                  // session fixation
  });
});
```

Why the strong version detects it: the assertion is the reuse attempt, which is exactly what an
attacker holding a stolen cookie does. The pre-logout check matters too — without it, a fixture
that never authenticated produces 401 everywhere and the test passes for the wrong reason.

The password-change case is a separate finding class: an attacker with a stolen session survives
the victim's remediation. WSTG-SESS-02 covers the cookie attributes; a `HttpOnly`/`Secure`/
`SameSite` assertion is worth adding beside these and costs one line.

Gap to state: a stateless JWT cannot be revoked by these tests unless the application keeps a
revocation list or server-side session state. If it does not, the honest outcome is a failing
test and a design finding, not a weaker assertion.

---

## 8. Account enumeration on password reset

`A07:2025` · `CWE-204` · ASVS V6, V16 · WSTG-IDNT-04, WSTG-ATHN-09

```python
# Weak: only exercises the known-good address, so the two responses are never compared
def test_password_reset_sends_email(client, alice):
    resp = client.post("/api/password/reset", json={"email": "alice@example.com"})
    assert resp.status_code == 202
```

```python
# Strong: assert the responses are indistinguishable, and that the token is single-use
import statistics, time

def _reset(client, email):
    return client.post("/api/password/reset", json={"email": email})

def test_reset_response_does_not_reveal_whether_the_account_exists(client, alice):
    known = _reset(client, "alice@example.com")
    unknown = _reset(client, "no-such-user@example.com")

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    # Header sets must match too: a Set-Cookie or a rate-limit header on one path only
    # is the same oracle in a different place.
    assert set(known.headers) - {"date", "content-length"} == \
           set(unknown.headers) - {"date", "content-length"}


def test_login_error_does_not_reveal_whether_the_account_exists(client, alice):
    wrong_pw = client.post("/api/login",
                           json={"email": "alice@example.com", "password": "wrong"})
    no_user = client.post("/api/login",
                          json={"email": "nobody@example.com", "password": "wrong"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


def test_reset_token_is_single_use(client, alice, mailbox):
    _reset(client, "alice@example.com")
    token = mailbox.latest_token_for("alice@example.com")

    first = client.post("/api/password/reset/confirm",
                        json={"token": token, "password": "new-test-passphrase-1"})
    assert first.status_code == 204

    second = client.post("/api/password/reset/confirm",
                         json={"token": token, "password": "new-test-passphrase-2"})
    assert second.status_code == 400
    assert verify_password("new-test-passphrase-1", db.reload(alice).password_hash)


def test_reset_token_expires(client, alice, mailbox, freeze_time):
    _reset(client, "alice@example.com")
    token = mailbox.latest_token_for("alice@example.com")
    freeze_time.advance(hours=25)
    resp = client.post("/api/password/reset/confirm",
                       json={"token": token, "password": "new-test-passphrase-3"})
    assert resp.status_code == 400
```

Why the strong version detects it: enumeration is a difference between two responses, so the
test has to make both requests and compare them. Comparing the header sets as well as the body
catches the common leak where only the existing-account path sets a rate-limit or session
header.

On timing: the response-time difference caused by hashing a password only for existing users is
a real oracle, but a wall-clock assertion in CI is flaky. Prefer the structural fix — hash
against a dummy record on the unknown-user path — and assert it deterministically if the code
exposes a seam. If you do measure, use many samples and a median comparison, run it in a
dedicated job, and treat a failure as a prompt to measure rather than a build gate.

```python
# If you measure, measure like this, and do not gate the build on it.
@pytest.mark.timing
def test_login_timing_is_comparable(client, alice):
    def median_ms(email):
        samples = []
        for _ in range(25):
            start = time.perf_counter()
            client.post("/api/login", json={"email": email, "password": "wrong"})
            samples.append((time.perf_counter() - start) * 1000)
        return statistics.median(samples)

    existing = median_ms("alice@example.com")
    missing = median_ms("nobody@example.com")
    assert abs(existing - missing) < max(25.0, 0.5 * min(existing, missing))
```

Gap to state: none of this covers registration, which is the other enumeration surface — "this
email is already taken" is the same oracle with a friendlier message. Test it the same way, and
if the product requires that message, record the accepted risk instead of asserting a behaviour
the product does not have.

---

## Sources

- OWASP WSTG v4.2 — <https://owasp.org/www-project-web-security-testing-guide/v42/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- CWE Top 25 (2025) — <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
