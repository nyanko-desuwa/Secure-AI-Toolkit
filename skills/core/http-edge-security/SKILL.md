---
name: http-edge-security
description: 'HTTP edge trust - reverse proxies, Host/X-Forwarded-*, request smuggling/desync, cache poisoning, header normalization. Triggers: "reverse proxy", "X-Forwarded-For", "Host header", "request smuggling", "HTTP desync", "cache poisoning", "CDN", "bảo mật reverse proxy", "đầu HTTP".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# HTTP Edge Security

The edge decides who the client is, which host was requested, and where the request ends.
When the app trusts a header the client can set, identity, routing, and cache keys all lie.
This skill owns reverse-proxy trust, Host and `X-Forwarded-*` handling, request smuggling
and desync, cache poisoning and deception, and method/header normalization at the HTTP edge.

## When to Use

- Configuring or reviewing a reverse proxy, load balancer, CDN, or API gateway in front of an app
- Application code that reads `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`, or similar
- Building absolute URLs, password-reset links, redirects, or tenant routing from request headers
- Investigating cache key design, CDN caching rules, or unexpected cached responses
- Reviewing HTTP/1.1 and HTTP/2 boundary handling between hops
- Hardening method override, absolute-form request lines, and header normalization

## When NOT to Use

| Concern | Route to |
|---|---|
| App-layer authz, BOLA, mass assignment, API rate limits by actor | `api-security` |
| CSP, XSS sinks, browser cookie flags, frontend origin isolation | `frontend-security` |
| SSH daemon, key auth, bastion hardening | `ssh-server` |
| Password, MFA, session, and OAuth flows in depth | `authentication` |
| Generic Top 10 triage without an edge surface | `owasp` |

Edge trust is infrastructure and the first hop of application code. Object authorization and
browser XSS controls live elsewhere.

## The Standard

OWASP Top 10 2025 supplies the risk language. ASVS 5.0 V4 (API/Web Service), V11 (HTTP
Request), V13 (Configuration), and V14 (Communication) supply testable requirements. CWE
names the defect class.

| Failure | One line | Primary pins |
|---|---|---|
| Proxy trust | App treats every peer as a trusted proxy | ASVS 4.1.3 · CWE-441 |
| Forwarded client IP | Client-set `X-Forwarded-For` becomes identity or rate-limit key | ASVS 4.1.3 · CWE-290 · A02 |
| Host header trust | `Host` drives redirects, reset links, virtual hosts, or cache keys | CWE-644 · A02/A05 |
| Request smuggling / desync | Two hops disagree on where one request ends | ASVS 4.2.1–4.2.4 · CWE-444 |
| Cache poisoning | Unkeyed attacker input enters a shared cache entry | CWE-444 · A02/A06 |
| Cache deception | Private response cached under a public-looking URL | CWE-525 · A01/A02 |
| Method / header normalization | Override headers or absolute-form change the effective verb or target | ASVS 4.1.4 · CWE-20 |

Detail in [references/](references/).

## Workflow

### 1. Map the hop chain

List every component that terminates or rewrites HTTP before the app: CDN, WAF, load
balancer, reverse proxy, sidecar, app server. Note protocol version on each hop
(HTTP/1.1 vs HTTP/2/3). Desync lives in disagreement between hops, not in one box alone.

```bash
grep -rnE "X-Forwarded-|X-Real-IP|req\.headers\.host|request\.host|getHeader\([\"']Host" src/ || true
```

### 2. Decide what is trusted, and from where

- Which source IPs may inject `X-Forwarded-*`?
- Does the edge strip client copies before appending its own?
- Does the app read the leftmost, rightmost, or a configured hop count?
- Is `Host` validated against an allowlist of canonical names?

An app that reads `X-Forwarded-For` without a trusted-proxy allowlist has no client IP.

### 3. Apply controls in this order

1. Terminate TLS and strip client-supplied intermediary headers at the real edge.
2. Allowlist proxy peers; reject or ignore forwarded headers from everyone else.
3. Canonicalize `Host` against configured server names before redirects or absolute URLs.
4. Make message framing consistent across hops (prefer HTTP/2 end-to-end, or normalize TE/CL).
5. Define explicit cache keys; do not cache authenticated or personalized responses by accident.
6. Disable method override unless required; normalize method and path once at the edge.
7. Bound header and request line size before the app buffers them.

### 4. Verify

Run [checklist.md](checklist.md). Edge and CDN config often lives outside the repo - mark
those items not verifiable from application code, never silently pass.

### 5. Report

Per finding: surface (proxy trust, Host, smuggling, cache, normalization), the request or
header that exploits it, CWE and standard pin, and the smallest fix. Prefer a concrete
request line over "possible desync".

## Severity

Rank by who can forge identity or poison shared state.

- Critical - unauthenticated auth bypass via forged forwarded identity; cross-user cache
  poison of private responses; confirmed request smuggling to internal routes
- High - Host-driven open redirect or password-reset poisoning; rate-limit or geo bypass via
  spoofed client IP; cache deception of session pages
- Medium - unkeyed header affects non-sensitive cache; missing normalization with no proven path
- Low - defence-in-depth header hygiene; verbose proxy errors with no direct exploit

A forged `X-Forwarded-For` used only for access logs is Low. The same header used as the
sole MFA step-up or admin allowlist is Critical.

## Related Skills

- `api-security` - object/function authorization, webhook trust, app-layer rate limits
- `frontend-security` - CSP, XSS, cookie scope in the browser
- `ssh-server` - SSH edge, not HTTP
- `owasp` - Top 10 2025 and ASVS chapter map
- `secure-code-review` - full-codebase review process

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification by surface
- [best-practices.md](best-practices.md) - patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - wrong fixes and why they fail
- [troubleshooting.md](troubleshooting.md) - conflicting requirements
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - OWASP, ASVS, CWE pins
- [examples/README.md](examples/README.md) - seven vulnerable/fixed pairs
