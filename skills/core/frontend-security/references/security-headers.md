# Security Headers

What each header blocks, what it does not, and the config to set it. Checked against MDN and the
OWASP Secure Headers Project on 2026-07-28.

`A02:2025` (Security Misconfiguration) · ASVS V3 (Web Frontend Security), V13 (Configuration)

Headers are cheap and shallow. Every one of them is a mitigation for a bug you should also fix.
A response with a perfect header set and an unsanitized sink still has an XSS finding.

## The set

| Header | Blocks | Does not block |
|---|---|---|
| `Content-Security-Policy` | Injected script execution, plugin content, base-tag repointing, framing | The injection itself. Exfiltration via navigation, DNS, or images |
| `Strict-Transport-Security` | Downgrade to HTTP after the first successful HTTPS visit | The first visit, unless preloaded. Anything on a compromised TLS path |
| `X-Content-Type-Options: nosniff` | MIME sniffing turning an upload into a script | A file served with a genuinely wrong `Content-Type` |
| `X-Frame-Options` | Framing, in browsers without `frame-ancestors` support | Nothing modern that `frame-ancestors` does not already cover |
| `Referrer-Policy` | Tokens and internal paths leaking in `Referer` | Data the page sends deliberately |
| `Permissions-Policy` | Unused camera, mic, geolocation, and similar APIs, including in iframes | Anything the feature is legitimately granted |
| `Cross-Origin-Opener-Policy` | Cross-window references from a popup opener chain, some XS-Leaks | In-origin attacks |
| `Cross-Origin-Resource-Policy` | Your resources being embedded cross-origin | Requests you serve with permissive CORS |
| `Cross-Origin-Embedder-Policy` | Loading cross-origin subresources without opt-in | Anything if you have not also set COOP |
| `Cache-Control` on authenticated responses | Sensitive pages persisting in a shared or disk cache | Data already rendered in the tab |

Note what is missing: `X-XSS-Protection` is obsolete. It was removed from Chrome and never
implemented usefully elsewhere, and in its filtered mode it introduced its own leaks. Setting it to
`0` is defensible; setting it to `1; mode=block` is cargo cult.

## nginx

```nginx
# Vulnerable: no security headers, and add_header without `always` is dropped on 4xx/5xx
location / {
    proxy_pass http://app;
}
```

```nginx
# Fixed
location / {
    proxy_pass http://app;

    add_header Content-Security-Policy "default-src 'self'; script-src 'nonce-$request_id' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
}
```

Two nginx-specific traps. Without `always`, the header is not sent on error responses — and error
pages are exactly where a reflected value often lands. And `add_header` in a nested block replaces
the parent's entire set rather than merging, so a `location /api` block with one `add_header` silently
drops every header defined at `server` level. Re-declare them or use a shared `include`.

## Express

```javascript
// Vulnerable: helmet defaults with CSP disabled because "it broke the app"
app.use(helmet({ contentSecurityPolicy: false }));
```

That is the single most common helmet configuration in the wild, and it removes the only header
that stops script execution. Fix the violations instead.

```javascript
// Fixed: explicit policy, per-request nonce
const crypto = require("node:crypto");
const helmet = require("helmet");

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [(req, res) => `'nonce-${res.locals.nonce}'`, "'strict-dynamic'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        connectSrc: ["'self'", "https://api.example.com"],
        imgSrc: ["'self'", "data:"],
        formAction: ["'self'"],
      },
    },
    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
  })
);
```

`useDefaults: false` is deliberate — helmet's default CSP includes `script-src 'self'`, which
combined with a user-upload path on the same origin is not a boundary.

## HSTS, carefully

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

`includeSubDomains` applies to every subdomain, including internal tools and legacy hosts that may
still be HTTP-only. `preload` is close to irreversible on a useful timescale: removal requires a
request to the preload list and then waiting for browser releases to ship. Start with a short
`max-age`, confirm nothing broke, then raise it. Do not add `preload` on the first deploy.

## Referrer-Policy choices

| Value | Sends | Use when |
|---|---|---|
| `no-referrer` | Nothing | Maximum privacy, breaks analytics and some CSRF heuristics |
| `same-origin` | Full URL to same origin only | Internal apps |
| `strict-origin-when-cross-origin` | Full URL same-origin, origin only cross-origin HTTPS, nothing on downgrade | Sensible default |
| `unsafe-url` | Full URL always | Never |

If a URL in your app ever contains a token — a password reset link, a magic login link, a signed
download URL — the referrer policy is load-bearing, not cosmetic. `unsafe-url` on such a page ships
the token to every third-party resource the page loads.

## Cookie attributes

Not a header set you configure globally, but part of the same review:

```javascript
res.cookie("sid", sessionId, {
  httpOnly: true,   // JS cannot read it. CWE-1004 if omitted
  secure: true,     // HTTPS only
  sameSite: "lax",  // CWE-1275 if set to "none" without reason
  path: "/",
  // Domain omitted: do not widen to subdomains unless required
});
```

`SameSite=Lax` blocks the cookie on cross-site POST, which stops the simplest CSRF. It is not a
substitute for a CSRF token: `Lax` still sends the cookie on top-level cross-site GET navigation,
so any state-changing GET is still reachable, and `SameSite` is site-scoped, not origin-scoped —
a sibling subdomain is same-site.

## Verify against the real origin

```bash
curl -sSI https://app.example.com/ | grep -i -E 'content-security|strict-transport|x-content-type|x-frame|referrer|permissions-policy|cross-origin'
```

Source inspection is not verification. A CDN, WAF, reverse proxy, or framework middleware can add,
strip, or overwrite any of these. Check an error response too:

```bash
curl -sSI https://app.example.com/does-not-exist | grep -i content-security
```

If the header is missing there, the 404 page is unprotected — and 404 pages frequently reflect the
requested path.

## Sources

- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- MDN HTTP headers — <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers>
- MDN Strict-Transport-Security — <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>
- MDN Set-Cookie — <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
- helmet — <https://helmetjs.github.io/>
