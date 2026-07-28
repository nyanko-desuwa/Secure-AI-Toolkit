# HTTP Edge Security Examples

Seven vulnerable/fixed pairs. These are defensive patterns, not production proxy configurations.

## Forwarded client identity — CWE-290

```javascript
// Vulnerable: client sends X-Forwarded-For: 10.0.0.8
app.set("trust proxy", true);
if (req.ip === "10.0.0.8") allowAdmin(req);
```

```javascript
// Fixed: trust only the known proxy network; authorize with a role
app.set("trust proxy", ["10.0.0.0/16"]);
requireAdminRole(req);
```

Why: an Internet peer cannot inject intermediary headers.

## Host-derived reset URL — CWE-644

```python
# Vulnerable: Host controls an emailed security link
url = f"https://{request.headers['host']}/reset?token={token}"
```

```python
# Fixed: configured origin controls the link
url = f"https://app.example.com/reset?token={token}"
```

Why: the attacker cannot replace the recipient's domain.

## Ambiguous framing awareness — CWE-444

```text
Vulnerable: a proxy accepts conflicting Content-Length and Transfer-Encoding while a backend parses
one differently. The request boundary is ambiguous.
```

```text
Fixed: the first hop rejects ambiguous framing and every hop uses patched, supported HTTP parsing.
Test only in an authorized staging environment.
```

Why: one unambiguous parser decision removes the desync prerequisite.

## Unkeyed cache input — CWE-444

```http
# Vulnerable: response reflects X-Forwarded-Host but cache key ignores it
X-Forwarded-Host: attacker.example
Cache-Control: public, max-age=300
```

```http
# Fixed: do not reflect it; cache only a configured canonical representation
Cache-Control: public, max-age=300
```

Why: no attacker-controlled unkeyed value reaches the cached body.

## Cache deception — CWE-525

```http
# Vulnerable: /account.css returns private account HTML and CDN caches by suffix
Cache-Control: public, max-age=600
```

```http
# Fixed: account routes are private regardless of path suffix
Cache-Control: private, no-store
```

Why: a public-looking path cannot turn private content into shared cache data.

## Absolute-form target — CWE-20

```text
Vulnerable: proxy routes `GET http://internal.example/admin HTTP/1.1` using the absolute target.
```

```text
Fixed: edge accepts the expected origin-form target and canonical Host only.
```

Why: routing has one normalized authority.

## Method override — CWE-20

```http
# Vulnerable: POST crosses a DELETE authorization rule
X-HTTP-Method-Override: DELETE
```

```text
Fixed: reject override headers globally, or allowlist them per legacy route before authorization.
```

Why: policy, logging, and handler agree on the effective method.
