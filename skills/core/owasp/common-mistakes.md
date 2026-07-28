# Common Mistakes

Failures seen repeatedly in AI-generated and hand-written code. Each entry: what it looks
like, why it fails, and the fix.

## Authentication mistaken for authorization

```python
@require_login
def get_document(doc_id):
    return db.query(Document).get(doc_id)
```

The decorator proves who the caller is. It says nothing about whether this document is
theirs. Any logged-in user enumerates every document by ID.

Fix: scope the query by actor. See [best-practices.md](best-practices.md#authorization).

## Ownership checked after fetch, then not used

```python
doc = db.query(Document).get(doc_id)
if doc.owner_id != current_user.id:
    logger.warning("unauthorized access attempt")
return doc
```

The check runs, logs, and returns the document anyway. A missing `raise` is easy to write
and easy to miss in review.

Fix: put the constraint in the query so there is nothing to forget.

## Parameterized query with an interpolated identifier

```python
cursor.execute(f"SELECT * FROM users ORDER BY {sort_column}")
```

People learn "use placeholders" and then hit a case where placeholders do not work —
column names, table names, `ASC`/`DESC` — and fall back to interpolation.

Fix: allowlist map from input to a known-safe identifier. Reject anything not in the map.

## Denylist validation

```javascript
if (input.includes("<script>")) reject();
```

Denylists enumerate what you thought of. `<img onerror=>`, `<svg onload=>`, case variants,
and encoded forms all pass.

Fix: allowlist the accepted shape, and encode at the sink. Blocking payloads is the wrong
layer.

## Validation used as if it were encoding

Input validated on the way in, then rendered raw because "it was already validated".
Validation constrains the input space. It does not make a string safe for HTML, SQL, and
shell simultaneously.

Fix: validate at the boundary, encode at every sink, independently.

## Catch-all that fails open

```python
try:
    authorized = check_permission(user, resource)
except Exception:
    authorized = True
```

Written to stop an outage from breaking the feature. Turns a dependency failure into an
authorization bypass.

Fix: `return False`, log the failure. See [best-practices.md](best-practices.md#fail-closed).

## File upload trusting the declared type

```python
if file.content_type == "image/png":
    file.save(f"/var/www/uploads/{file.filename}")
```

Three problems: `content_type` is attacker-controlled, `filename` allows traversal, and the
destination is inside the web root — so an uploaded script may be executed.

Fix: verify the magic number, generate the stored filename yourself, store outside the web
root, and serve with a fixed `Content-Type` plus
`Content-Disposition: attachment` where appropriate.

## Secrets committed with intent to remove later

```python
API_KEY = "sk-live-4eC39H..."  # TODO: move to env
```

The TODO does not stop the commit. Once in git history, the secret is exposed even after
the line is deleted.

Fix: read from the environment from the first line of code. If a secret has already been
committed, rotate it — deleting the line is not remediation.

## Password hashed with a fast hash

```python
hashlib.sha256(password.encode()).hexdigest()
```

SHA-256 is designed to be fast, which is exactly wrong for passwords. Salting helps against
rainbow tables and does nothing against a GPU.

Fix: Argon2id, or bcrypt where unavailable. Use the library's default cost, do not lower it.

## Timing-unsafe secret comparison

```python
if provided_token == stored_token:
```

`==` short-circuits on the first differing byte, leaking length and prefix through timing.

Fix: `secrets.compare_digest(provided, stored)` or the equivalent constant-time helper.

## SSRF from a user-supplied URL

```python
resp = requests.get(request.json["callback_url"])
```

Reaches internal services, cloud metadata endpoints, and `localhost`. Redirect following
defeats naive hostname checks. SSRF has no standalone slot in the 2025 Top 10 — report it
under A01 or A06 with CWE-918.

Fix: allowlist scheme and host, resolve the hostname and reject private ranges, disable
redirects, and re-check the resolved address after any redirect you do allow.

## Verbose errors as a debugging convenience

```javascript
res.status(500).json({ error: err.message, stack: err.stack });
```

Ships database schema, file paths, and library versions to whoever asks.

Fix: a correlation ID to the client, the detail to the log.

## Rate limiting only on the login endpoint

Password reset, token refresh, OTP verification, and search are all abusable. Login is
simply the one people remember.

Fix: rate limit by actor and by IP on every expensive or sensitive flow.

## Logging the object that contains the secret

```python
logger.info("auth request: %s", request.json)
```

The password is now in the log, in plaintext, replicated to wherever logs ship.

Fix: log named fields explicitly. Never log a whole request or user object.
