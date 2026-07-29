# OWASP Examples

Vulnerable code next to its fix. Each example names the Top 10 category, the CWE, and why the
fix actually closes the hole rather than just looking safer.

Read these as patterns, not as drop-in code. The language is incidental - the mistake is not.

## Contents

- [Broken object level authorization](#broken-object-level-authorization) - A01, CWE-639
- [SQL injection through a sort parameter](#sql-injection-through-a-sort-parameter) - A05, CWE-89
- [Path traversal in a download endpoint](#path-traversal-in-a-download-endpoint) - A01, CWE-22
- [SSRF in a webhook fetcher](#ssrf-in-a-webhook-fetcher) - A06, CWE-918
- [Failing open on a policy error](#failing-open-on-a-policy-error) - A10, CWE-636
- [File upload trusting the declared type](#file-upload-trusting-the-declared-type) - A08, CWE-434
- [JWT accepting the algorithm from the token](#jwt-accepting-the-algorithm-from-the-token) - A07, CWE-347

---

## Broken object level authorization

`A01:2025` · `CWE-639` · ASVS V8

The most common real-world API vulnerability. Authentication works, authorization is absent.

```javascript
// Vulnerable: authenticated is not the same as authorized
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  if (!order) return res.status(404).json({ error: "not_found" });
  res.json(order);
});
```

Any logged-in user increments the ID and reads every order in the system.

```javascript
// Fixed: ownership is part of the lookup
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.order.findFirst({
    where: { id: req.params.id, customerId: req.user.id },
  });
  if (!order) return res.status(404).json({ error: "not_found" });
  res.json(order);
});
```

Why this works: there is no branch to forget. A missing order and someone else's order return
the same 404, so the endpoint does not confirm which IDs exist.

The tempting wrong fix is a UUID primary key. That is obscurity - it raises the cost of guessing
without removing the ability to read. IDs leak through exports, referrer headers, and logs.

---

## SQL injection through a sort parameter

`A05:2025` · `CWE-89` · ASVS V1

Parameterization covers values. It does not cover identifiers, which is where this survives in
otherwise careful codebases.

```python
# Vulnerable: values are parameterized, the column name is not
def list_invoices(user_id: int, sort: str, direction: str):
    query = f"SELECT * FROM invoices WHERE user_id = %s ORDER BY {sort} {direction}"
    return db.execute(query, (user_id,)).fetchall()
```

`sort` of `id; DROP TABLE invoices--` or a subquery in the ORDER BY clause both land.

```python
# Fixed: identifiers resolved through an allowlist, never interpolated
SORT_COLUMNS = {"created": "created_at", "total": "total_cents", "status": "status"}
DIRECTIONS = {"asc": "ASC", "desc": "DESC"}

def list_invoices(user_id: int, sort: str, direction: str):
    column = SORT_COLUMNS.get(sort)
    order = DIRECTIONS.get(direction)
    if column is None or order is None:
        raise BadRequest("invalid_sort")

    query = f"SELECT * FROM invoices WHERE user_id = %s ORDER BY {column} {order}"
    return db.execute(query, (user_id,)).fetchall()
```

Why this works: the f-string now interpolates only values the server chose. User input selects a
key; it never becomes SQL. Escaping or a regex on `sort` would be weaker - you would be trying
to enumerate every dangerous construction instead of enumerating the three safe ones.

---

## Path traversal in a download endpoint

`A01:2025` · `CWE-22` · ASVS V5

```python
# Vulnerable: join follows ../ wherever it leads
@app.get("/download")
def download(name: str):
    path = os.path.join(UPLOAD_DIR, name)
    return send_file(path)
```

`name=../../../../etc/passwd` leaves the upload directory. On Windows, `..\\` and absolute
paths like `C:\\` do the same, and `os.path.join` discards `UPLOAD_DIR` entirely when handed an
absolute path.

```python
# Fixed: resolve, then confirm the result is still inside the directory
from pathlib import Path

UPLOAD_DIR = Path("/srv/uploads").resolve()

@app.get("/download")
def download(name: str):
    target = (UPLOAD_DIR / name).resolve()
    if not target.is_relative_to(UPLOAD_DIR) or not target.is_file():
        raise NotFound()
    return send_file(target)
```

Why this works: the check happens after resolution, so `..` segments and symlinks are already
collapsed. Checking before resolution - rejecting strings containing `..` - misses encoded
variants and symlinks that point outside.

Better still where the design allows it: store an opaque ID, look the real filename up in the
database, and never accept a path from the client at all.

---

## SSRF in a webhook fetcher

`A06:2025` · `CWE-918` · ASVS V2, V12

```python
# Vulnerable: the server will fetch anything, including its own metadata service
def preview_url(url: str) -> str:
    return requests.get(url, timeout=5).text[:2000]
```

Cloud metadata endpoints, internal admin panels, and localhost services are all reachable from
here. On AWS this is a credential disclosure, not just an information leak.

```python
# Fixed: scheme allowlist, resolve first, reject private targets, no redirects
import ipaddress, socket
from urllib.parse import urlparse

def preview_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise BadRequest("unsupported_url")

    infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise BadRequest("unsupported_url")

    resp = requests.get(url, timeout=5, allow_redirects=False, stream=True)
    return resp.raw.read(2000, decode_content=True).decode("utf-8", "replace")
```

Why this works: every resolved address is checked, not just the first, and redirects are off so
a permitted host cannot forward the request to `169.254.169.254`.

Honest limitation: this is still vulnerable to DNS rebinding, because the address is resolved
once for the check and again by `requests` for the connection. Closing that gap means pinning
the validated IP into the connection - an egress proxy with an allowlist is the more robust
answer in production. Say so rather than implying the check is complete.

---

## Failing open on a policy error

`A10:2025` · `CWE-636` · ASVS V16

```java
// Vulnerable: a policy service outage grants everyone access
public boolean canPublish(User actor, Article article) {
    try {
        return policyClient.check(actor.getId(), article.getId(), "publish");
    } catch (Exception e) {
        log.warn("policy check failed, allowing");
        return true;
    }
}
```

This is usually written to stop an outage becoming a customer-facing error. The effect is that
the cheapest way to bypass authorization is to make the policy service unreachable.

```java
// Fixed: unavailable means denied, and the failure is loud
public boolean canPublish(User actor, Article article) {
    try {
        return policyClient.check(actor.getId(), article.getId(), "publish");
    } catch (PolicyUnavailableException e) {
        log.error("policy_check_failed actor={} article={}", actor.getId(), article.getId(), e);
        throw new ServiceUnavailableException("authorization_unavailable");
    }
}
```

Why this works: the caller cannot mistake a failure for a grant. Returning `false` is also
correct; throwing is better here because a 503 tells the client to retry, while a 403 tells them
they lack permission, which is not what happened.

Note the narrowed catch. `catch (Exception e)` also swallows programming errors that should
surface in tests.

---

## File upload trusting the declared type

`A08:2025` · `CWE-434` · ASVS V5

```php
// Vulnerable: extension and Content-Type both come from the client
$ext = pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION);
if ($_FILES['avatar']['type'] === 'image/png') {
    move_uploaded_file($_FILES['avatar']['tmp_name'], "/var/www/html/avatars/$name.$ext");
}
```

Two problems compound. The type check is a client-supplied header, and the destination is inside
the web root, so an uploaded `.php` file becomes remote code execution.

```php
// Fixed: verify content, generate the name, store outside the web root
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['avatar']['tmp_name']);

$allowed = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/webp' => 'webp'];
if (!isset($allowed[$mime])) {
    throw new InvalidArgumentException('unsupported_image');
}

$name = bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
move_uploaded_file($_FILES['avatar']['tmp_name'], "/srv/uploads/avatars/$name");
```

Why this works: the type comes from the file's own bytes, the filename is server-generated so
no extension or traversal sequence survives, and the storage directory is not served as script.

Remaining gaps worth naming: magic-number detection can be fooled by polyglot files. For images
specifically, re-encoding through an image library strips embedded payloads and is the stronger
control. Enforce a size limit too, or the endpoint is a disk-exhaustion vector.

---

## JWT accepting the algorithm from the token

`A07:2025` · `CWE-347` · ASVS V9

```javascript
// Vulnerable: the token's own header decides how it is verified
const payload = jwt.verify(token, process.env.JWT_SECRET);
```

Depending on the library version and configuration, a token with `"alg": "none"` or one signed
with `HS256` against a public key can be accepted. The attacker controls the header.

```javascript
// Fixed: the server states the algorithm, issuer, and audience
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"],
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  clockTolerance: 5,
});
```

Why this works: verification parameters come from server configuration, so nothing in the token
influences how it is checked. Pinning issuer and audience stops a valid token minted for another
service from being replayed against this one.

Also worth knowing: a JWT cannot be revoked before it expires. If logout must take effect
immediately, keep server-side session state or a revocation list - a short expiry narrows the
window but does not close it.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cheatsheetseries.owasp.org/>
- <https://cwe.mitre.org/top25/>
