# Frontend Security

The browser is an attacker-controlled runtime. A frontend control protects a user's browser
session from injected code and confused-deputy actions. It does not authorize the user: every
permission, price, role, and state change still needs server-side enforcement.

## Purpose

This skill gives an AI assistant a repeatable way to review browser sinks, trace untrusted
sources, select a control for the sink, and add structural protections such as CSP and security
headers. Each control names an OWASP Top 10 2025 category, ASVS 5.0 chapter, and CWE where one
applies.

## How It Works

Plain Markdown. Nothing executes. Read `SKILL.md` first, then pull in the supporting file for the
review. The workflow is grep-first because DOM XSS is concentrated in a short list of APIs.

```text
SKILL.md                    workflow, sink/source lists, severity
README.md                   purpose, configuration, limitations
checklist.md                pre-return verification
best-practices.md           durable patterns with vulnerable/fixed pairs
common-mistakes.md         tempting fixes that fail
troubleshooting.md         conflicts and unverifiable deployment state
prompts.md                 focused review prompts and anti-patterns
references/
  csp-guide.md             CSP Level 3 and Trusted Types
  security-headers.md      header controls and limits
  asvs-v3-web-frontend.md  ASVS 5.0 V3 chapter scope, and V1/V7 overlap
examples/README.md         eight vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Scope | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A01, A02, A03, A05 | 2026-07-28 |
| OWASP ASVS | 5.0.0, released 2025-05-30 | V1, V2, V3, V13, V15 | 2026-07-28 |
| CSP | Level 3 | nonce policies, `strict-dynamic`, Trusted Types integration | 2026-07-28 |
| DOMPurify | 3.4.12 | explicit sanitization when HTML must remain HTML | 2026-07-28 |

CWE mappings used here include CWE-79 (XSS), CWE-352 (CSRF), CWE-601 (open redirect), CWE-1021
(clickjacking), CWE-1275 (`SameSite`), CWE-346 (origin validation), CWE-1321 (prototype
pollution), CWE-353 (missing integrity check), and CWE-1004 (missing `HttpOnly`).

## Configuration

The skill has no build step or runtime configuration. The recommended application controls do.
Pin DOMPurify if it is needed:

```bash
npm install --save-exact dompurify@3.4.12
```

Generate CSP nonces per response with a cryptographically secure random source. Never reuse the
literal nonce shown in an example. Send the CSP from the server or a trusted edge layer, then
verify the deployed response with `curl -I`; source code cannot prove which header wins after a
CDN or reverse proxy modifies it.

## Example Usage

Review sinks and their dataflow:

```text
Grep src/ for innerHTML, outerHTML, insertAdjacentHTML, document.write,
dangerouslySetInnerHTML, v-html, {@html}, bypassSecurityTrust, eval, new Function, and
string-based timers. For each hit trace the source. Report file:line, source, sink, exploit
path, OWASP category, ASVS chapter, CWE, severity, and fixed code. Skip literal-only sinks.
```

Review browser policy:

```text
Review the deployed Content-Security-Policy and security headers. Tell me which concrete
XSS, framing, MIME-sniffing, and referrer paths each header blocks, what it does not block,
and give one replacement policy if the current policy uses unsafe-inline or unsafe-eval.
```

Review token placement:

```text
Our SPA stores an access token in localStorage. Compare that design with an HttpOnly,
Secure, SameSite cookie and include the CSRF controls the cookie design requires. Do not
call the frontend check authorization.
```

More prompts are in [prompts.md](prompts.md).

## Limitations

- This is guidance, not taint analysis. A sink fed through a state store or several modules can
  be missed. Pair it with a DOM XSS scanner and tests.
- It cannot verify deployed headers, CSP report delivery, cookie flags, or browser support. Test
  the real origin with `curl -I` and browser developer tools.
- Sanitizer settings are context-specific. A rich-text allowlist is not suitable for an HTML
  attribute, CSS value, SVG, or URL. Test accepted payloads.
- Trusted Types and CSP Level 3 support varies by browser. They are structural layers, not a
  replacement for safe rendering.
- Examples use JavaScript/TypeScript, React, Vue, and nginx. Angular and Svelte are described in
  prose; native WebViews, Blazor, and HTMX are out of scope.
- ASVS mapping is at chapter level, not individual requirement IDs. Do not claim an ASVS level
  without a requirement-by-requirement assessment.
- CSP cannot repair server-side authorization, unsafe API responses, or a compromised dependency.

## Security Notes

`best-practices.md`, `common-mistakes.md`, and `examples/README.md` contain deliberately
vulnerable code. Every vulnerable block is labelled and paired with a fixed version. Payloads
are illustrative only. Hostnames, nonces, tokens, and keys are placeholders.

The client is not a trust boundary for authorization. A hidden button, disabled form, or route
guard changes appearance, not what an attacker can send to the API.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP XSS Prevention — <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- OWASP DOM XSS Prevention — <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
- OWASP CSRF Prevention — <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- CSP Level 3 — <https://www.w3.org/TR/CSP3/>
- Trusted Types — <https://w3c.github.io/trusted-types/dist/spec/>
- DOMPurify — <https://github.com/cure53/DOMPurify>
