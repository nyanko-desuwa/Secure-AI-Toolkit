# ASVS 5.0 — V1 and V3 for Frontend Work

OWASP Application Security Verification Standard 5.0.0, released 2025-05-30. Source:
<https://owasp.org/www-project-application-security-verification-standard/>. Checked 2026-07-28.

This file is a chapter-level map, not a requirement list. ASVS 5.0 requirement IDs are versioned
and change between editions — read them from the official release rather than quoting an ID from
memory. Nothing in this skill claims an ASVS level; a level claim needs a requirement-by-requirement
assessment against the published CSV.

## Which chapter for which finding

| Frontend concern | Chapter | Paired Top 10 2025 | CWE |
|---|---|---|---|
| Encoding at an HTML, attribute, URL, CSS, or JS sink | V1 Encoding and Sanitization | A05 Injection | CWE-79 |
| Sanitizing user-supplied HTML | V1 | A05 | CWE-79 |
| Browser policy: CSP, Trusted Types, headers | V3 Web Frontend Security | A02 Security Misconfiguration | CWE-1275 |
| Cookie attributes, `SameSite`, CSRF defence | V3 (with V7 Session Management) | A02, A07 | CWE-352, CWE-1004 |
| Framing and UI redress | V3 | A02 | CWE-1021 |
| `postMessage` origin validation | V3 | A05 | CWE-346 |
| Redirect target validation | V2 Validation and Business Logic | A01 Broken Access Control | CWE-601 |
| Prototype pollution through untrusted keys | V2 (with V15 Secure Coding) | A05 | CWE-1321 |
| Third-party script integrity, SRI | V3 (with V15) | A03 Software Supply Chain Failures | CWE-353 |
| Header delivery and environment config | V13 Configuration | A02 | — |

The full chapter list for 5.0.0 is V1 Encoding and Sanitization, V2 Validation and Business Logic,
V3 Web Frontend Security, V4 API and Web Service, V5 File Handling, V6 Authentication,
V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC,
V11 Cryptography, V12 Secure Communication, V13 Configuration, V14 Data Protection,
V15 Secure Coding and Architecture, V16 Security Logging and Error Handling, V17 WebRTC.

## What V1 asks of a frontend

V1 is about the sink, not the input. The chapter's shape is that output encoding is selected by the
context the value lands in, and that sanitization is a separate, narrower activity from validation.

Practical reading for a browser codebase:

- Text goes through a text sink. `textContent`, or framework interpolation. No HTML string.
- Where HTML must survive, it is sanitized by a maintained library with an explicit allowlist, and
  sanitized on output rather than on storage.
- Each context gets its own control. An allowlist tuned for an article body is not a control for an
  attribute value, a CSS declaration, or an SVG fragment.
- Dynamic code construction — `eval`, `new Function`, string timers — is removed rather than
  guarded. There is no encoding that makes user data safe as code.

A finding that cites V1 should name the sink and the context. "Unencoded output" without the
context is not actionable, because the fix differs per context.

## What V3 asks of a frontend

V3 is the chapter that exists because the browser is a hostile runtime. It covers the policies the
server sends to constrain what the page can do, and the client-side patterns that keep a session
from being driven by another origin.

The clusters worth reviewing together:

- Content Security Policy. A policy that a reviewer would accept uses per-response nonces or
  hashes, carries `object-src 'none'` and `base-uri 'none'`, and has no `unsafe-inline` on
  `script-src`. See [csp-guide.md](csp-guide.md).
- Trusted Types. `require-trusted-types-for 'script'` plus a `trusted-types` allowlist, so an
  injected script cannot create its own pass-through policy.
- Cookies and tokens. `HttpOnly`, `Secure`, an intentional `SameSite`, and no credential in
  `localStorage`, `sessionStorage`, a URL, or the bundle.
- CSRF. A token or equivalent server-side check on every state-changing request that authenticates
  by cookie. `SameSite` is a mitigation, not the control.
- Framing. `frame-ancestors`, with `X-Frame-Options` only as a legacy fallback.
- Cross-document messaging. Exact target origin on send, exact `event.origin` comparison on
  receive, and schema validation of `event.data` after the origin check.
- Third-party code. Pinned immutable URLs, SRI with `crossorigin`, sandboxed iframes for embeds
  you do not control.
- Browser storage. Nothing sensitive in a store readable by script on the origin.

## What ASVS does not settle

- It does not verify deployment. A requirement about a header is satisfied by the header the browser
  receives, which source code cannot prove. Confirm with `curl -I` against the real origin, on a
  success response and an error response.
- It does not rank. ASVS is a requirement set; the Top 10 is a risk ranking. Use ASVS to decide what
  to check and the Top 10 category to communicate severity.
- It does not replace the sink fix with a policy. A page with a nonce-based CSP and an unsanitized
  `innerHTML` assignment still has a V1 finding. Report both, and say which one is the vulnerability
  and which is the missing mitigation.
- It does not cover client platforms outside the web frontend. Native WebViews, mobile shells, and
  desktop wrappers have their own threat surface that V3 does not address.

## Using a chapter citation honestly

Cite the chapter, name the concrete failure, and state what you could not check:

```text
V3 (Web Frontend Security) · A02:2025 · CWE-352 — POST /api/account/email authenticates by
session cookie and accepts no CSRF token. Any cross-site page can submit the form on behalf of a
logged-in user. Cookie is SameSite=Lax, which blocks the cross-site POST in current browsers but
is a mitigation, not the control. Deployed cookie attributes not verified — read from source only.
```

That is defensible. "Violates ASVS V3" on its own is not, and neither is a requirement ID that was
not read from the published standard.

## Sources

- OWASP ASVS project — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP XSS Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- OWASP CSRF Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- CWE — <https://cwe.mitre.org/>
