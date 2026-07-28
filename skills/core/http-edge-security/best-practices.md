# HTTP Edge Best Practices

The edge must establish facts before the application uses them. Each pattern maps to ASVS 5.0 and a CWE.

## Trust a configured proxy set, not all peers

`ASVS 4.1.3` · `CWE-441` · `CWE-290`

```javascript
// Vulnerable: every Internet client may claim to be a proxy
app.set("trust proxy", true);
app.get("/admin", (req, res) => {
  if (req.ip === "10.0.0.8") return res.send("ok");
  res.sendStatus(403);
});
```

```javascript
// Fixed: only the load balancer's private network may supply forwarded data
app.set("trust proxy", ["10.0.0.0/16"]);
app.get("/admin", requireAdminRole, (req, res) => res.send("ok"));
```

Why this works: Express only derives client address from a known intermediary. The role check does
not turn a mutable IP header into authorization.

## Build public URLs from configuration

`CWE-644` · `ASVS V13`

```python
# Vulnerable: Host: reset.attacker.example poisons the emailed link
link = f"https://{request.headers['host']}/reset?token={token}"
```

```python
# Fixed: deployment configuration is the public authority
PUBLIC_ORIGIN = "https://app.example.com"
link = f"{PUBLIC_ORIGIN}/reset?token={token}"
```

Why this works: the request can no longer choose the recipient's domain. A Host allowlist alone is
useful, but configuration is safer for a security-sensitive absolute URL.

## Reject ambiguous request framing

`CWE-444` · `ASVS V4`

```nginx
# Vulnerable: forwards ambiguous requests to a different parser downstream
proxy_pass http://app;
```

```nginx
# Fixed: reject unsupported framing at the first HTTP/1.1 hop
if ($http_transfer_encoding != "") { return 400; }
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_pass http://app;
```

Why this works: the exact directive set depends on the proxy. The control is one parser and one
framing rule at every boundary; validate it in a controlled staging lab. Do not copy this snippet
as a universal smuggling fix.

## Make cache eligibility explicit

`CWE-525` · `CWE-444`

```http
# Vulnerable: personalized response may enter a shared cache
Cache-Control: public, max-age=300
```

```http
# Fixed: user-specific content cannot be stored by a shared cache
Cache-Control: private, no-store
Vary: Authorization
```

Why this works: `private, no-store` closes the shared-cache path. `Vary` alone partitions entries;
it does not make sensitive data safe to store.

## Reject method override unless it is a product requirement

`ASVS 4.1.4` · `CWE-20`

```javascript
// Vulnerable: a POST crosses a middleware rule written only for DELETE
app.use(methodOverride("X-HTTP-Method-Override"));
```

```javascript
// Fixed: route the actual verb and reject override headers at the edge
app.use((req, res, next) => {
  if (req.headers["x-http-method-override"]) return res.sendStatus(400);
  next();
});
```

Why this works: authorization and observability see one method. If legacy clients require an
override, allowlist it per route and authorize after normalization.
