---
name: frontend-security
description: 'Apply browser-side security controls when writing, reviewing, or hardening client code. Covers XSS and DOM sinks, framework escape hatches, sanitization, CSP, Trusted Types, CSRF, token storage, clickjacking, postMessage, and security headers. Maps to OWASP Top 10 2025 A05/A02 and ASVS 5.0 V1/V3. Triggers: "XSS", "CSP", "innerHTML", "dangerouslySetInnerHTML", "postMessage", "CSRF", "security headers", "clickjacking", "bảo mật frontend", "lỗ hổng trình duyệt".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Frontend Security

The browser is an attacker-controlled runtime. This skill covers what runs on the client and
what the client is trusted with.

## When to Use

- Rendering anything that came from a user, an API, a URL, or `postMessage`
- Reaching for `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, or `bypassSecurityTrust*`
- Deciding where to keep an access token
- Writing or reviewing a CSP, or any security header set
- Adding a third-party script, an iframe, or a `window.open`
- Building a redirect, a deep link, or a cross-window message channel

## The Rule That Drives Everything

Nothing the client enforces is a security control. Validation, role checks, price
calculation, and rate limiting all run again on the server. Frontend security is about
protecting the user's browser session from injected code - not about protecting the server
from the user.

Two failure classes follow:

| Class | What the attacker gets | Primary category |
|---|---|---|
| XSS | Code execution in the user's origin. Reads any token, performs any action the user can | A05:2025 · CWE-79 |
| Confused deputy | The browser sends the user's credentials on the attacker's behalf (CSRF, clickjacking) | A02:2025 · CWE-352, CWE-1021 |

## Standards Map

| Concern | Top 10 2025 | ASVS 5.0 | CWE |
|---|---|---|---|
| XSS, all types | A05 Injection | V1 Encoding and Sanitization | CWE-79 |
| DOM sinks, Trusted Types | A05 Injection | V3 Web Frontend Security | CWE-79 |
| CSP, headers, cookie flags | A02 Security Misconfiguration | V3, V13 Configuration | CWE-1275 |
| CSRF | A02 Security Misconfiguration | V3 Web Frontend Security | CWE-352 |
| Clickjacking | A02 Security Misconfiguration | V3 Web Frontend Security | CWE-1021 |
| Open redirect | A01 Broken Access Control | V2 Validation and Business Logic | CWE-601 |
| Third-party script, SRI | A03 Software Supply Chain Failures | V3, V15 | CWE-353 |
| Prototype pollution | A05 Injection | V2 Validation and Business Logic | CWE-1321 |
| `postMessage` origin | A05 Injection | V3 Web Frontend Security | CWE-346 |

## Workflow

### 1. Find the sinks

Search before reading. A frontend review starts with a grep, because DOM XSS lives in a
short list of APIs:

```bash
rg -n "innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|\{@html|bypassSecurityTrust|\beval\(|new Function|setTimeout\(\s*[\"'\`]" src/
```

Then the URL-shaped sinks: assignments to `href`, `src`, `action`, `formaction`,
`location`, `window.open`, and `srcdoc`.

### 2. Trace to a source

A sink is only a vulnerability if untrusted data reaches it. Sources, roughly in order of
how often they are missed:

`location.hash` · `location.search` · `location.pathname` · `document.referrer` ·
`window.name` · `postMessage` data · `localStorage` · API responses · `document.cookie`

The hash is the one people miss most, because it never reaches the server and so never
appears in server logs or a WAF.

### 3. Choose the control by sink type

| Sink | Control |
|---|---|
| Text content | Framework interpolation, or `textContent`. Never build HTML |
| HTML that must stay HTML | DOMPurify with an explicit allowlist config |
| URL attribute | Parse and check the scheme against `http`/`https`/`mailto` |
| Attribute name or event handler | Do not make it dynamic. Map through an allowlist |
| CSS value | Do not interpolate user input into `style`. Use a class |
| `eval` family | Remove it. There is no safe way to pass user data here |

### 4. Add the structural layer

Per-sink fixes are per-sink. They do not survive the next developer. Add a nonce-based CSP
with `strict-dynamic`, `object-src 'none'`, and `base-uri 'none'`, then
`require-trusted-types-for 'script'` to turn every remaining DOM sink into a runtime error.
See [references/csp-guide.md](references/csp-guide.md).

### 5. Verify

Run [checklist.md](checklist.md). Headers cannot be confirmed from source alone - if you
only read the code, say the deployed configuration is unverified.

## Severity

Rank by what the attacker can reach, not by the sink's name.

- Critical - stored XSS on an authenticated page, or XSS on the login/session origin.
  One visit, full account takeover, no interaction needed.
- High - reflected or DOM XSS reachable by a link. Needs a click, but the payload is in the
  attacker's URL. CSRF on a state-changing endpoint with real impact.
- Medium - self-XSS requiring the victim to paste a payload. Clickjacking with a plausible
  UI redress path. Missing SRI on a script from a controlled CDN.
- Low - a missing defence-in-depth header with no reachable sink behind it.

A missing CSP is not a vulnerability on its own. It is a missing mitigation. Report it as
one, with the XSS finding it would have contained, or it gets ignored.

## Related Skills

- `owasp-security` - the standards map these controls trace to
- `api-security` - the server side of CSRF, CORS, and token validation
- `authentication` - session and token lifecycle
- `supply-chain-security` - dependency and third-party script risk in depth

## Supporting Files

- [README.md](README.md) - purpose, configuration, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when a control cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/csp-guide.md](references/csp-guide.md) - CSP Level 3, Trusted Types
- [references/security-headers.md](references/security-headers.md) - header set, what each blocks
- [references/asvs-v3-web-frontend.md](references/asvs-v3-web-frontend.md) - ASVS 5.0 V3 scope and overlap
- [examples/README.md](examples/README.md) - eight vulnerable/fixed pairs
