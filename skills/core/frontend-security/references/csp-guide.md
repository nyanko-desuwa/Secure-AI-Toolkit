# Content Security Policy and Trusted Types

CSP Level 3 — <https://www.w3.org/TR/CSP3/>. Trusted Types —
<https://w3c.github.io/trusted-types/dist/spec/>. Both checked 2026-07-28. Both are living
documents: re-read the source before quoting a section number, and do not cite a directive name
from memory.

`A02:2025` (Security Misconfiguration) · ASVS V3 (Web Frontend Security), V13 (Configuration) ·
CWE-79

## What CSP is for

CSP is a second layer. It limits what an injected string can do after your escaping has already
failed. It is not an XSS fix, and a policy added to a page with an unsanitized `innerHTML` sink
still has an XSS finding behind it — report both.

Ranked by what actually holds up:

| Policy style | Stops injected `<script>` | Notes |
|---|---|---|
| Per-response nonce plus `strict-dynamic` | Yes | The only style worth deploying new |
| Hashes for a fixed set of inline scripts | Yes | Fine for static sites, painful with a build step |
| Host allowlist | Usually not | One JSONP endpoint or one unsafe framework build on the list defeats it |
| Anything with `unsafe-inline` on `script-src` | No | This is the default state dressed up as a policy |

## A policy that does something

```nginx
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'nonce-$request_id' 'strict-dynamic' https: 'unsafe-inline';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' https://api.example.com;
  font-src 'self';
  form-action 'self';
  require-trusted-types-for 'script';
" always;
```

Reading it directive by directive:

- `script-src 'nonce-...'` — only scripts carrying this response's nonce run. The nonce must be at
  least 128 bits from a CSPRNG, regenerated per response, and never reused across responses or
  cached.
- `'strict-dynamic'` — a script that already passed the nonce check may create further scripts.
  Without it, every dynamically injected script (analytics loaders, bundle chunk loaders) breaks.
- `https: 'unsafe-inline'` — deliberate fallback, not a mistake. Browsers that support
  `strict-dynamic` ignore both; browsers that do not fall back to the weaker pair rather than
  blocking the whole app. If you have no legacy browsers to support, drop them.
- `object-src 'none'` — kills `<embed>`, `<object>`, and Flash-era plugin script execution. Cheap,
  no downside.
- `base-uri 'none'` — without it, an injected `<base href="https://attacker.example">` repoints
  every relative script URL. This is the directive people forget, and its absence undoes a nonce
  policy on a page with relative script paths.
- `frame-ancestors 'none'` — clickjacking. Supersedes `X-Frame-Options` where supported. Keep both
  for older browsers.
- `connect-src` — bounds where injected code can exfiltrate to. Not perfect (DNS prefetch,
  navigation, and images all leak) but it raises the cost.

The nonce must reach the tag:

```html
<script nonce="{{ nonce }}" src="/assets/app.js"></script>
```

In nginx, `$request_id` is a convenient per-request unique value. Confirm your build actually
templates the same value into the markup; a nonce in the header that appears nowhere in the HTML
blocks every script, and a nonce hardcoded in both is not a nonce.

## Deploy in report-only first

```nginx
add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'nonce-$request_id' 'strict-dynamic'; report-uri /csp-report" always;
```

Enforcing a new policy blind takes the app down. Run report-only, watch the violations for a real
traffic cycle, fix them, then switch the header name.

Two things about reports: the endpoint receives attacker-controllable content, so treat report
bodies as untrusted input and never render them; and browser extensions generate enormous volumes
of noise violations that are not your bugs. Filter by `blocked-uri` scheme before drawing
conclusions.

## Common bypasses to check for in an existing policy

- A host on the allowlist serving a JSONP endpoint. `script-src https://cdn.example.com` plus
  `cdn.example.com/jsonp?callback=alert(1)` is arbitrary execution.
- A host on the allowlist serving an old AngularJS or similar build. The template engine becomes
  the interpreter.
- Missing `base-uri` on a page using relative script paths.
- `unsafe-eval` present. Any injection that reaches a template compiler or `JSON.parse`
  replacement now runs code.
- Missing `object-src`.
- A wildcard subdomain (`*.example.com`) where any team can deploy static files.
- The header set in a `<meta>` tag: `frame-ancestors`, `report-uri`, and `sandbox` are ignored
  there.

## Trusted Types

CSP stops injected script from running. Trusted Types stops the injection reaching a DOM sink in
the first place, by making the sink refuse a plain string.

```javascript
// Vulnerable: the sink accepts any string, from anywhere
element.innerHTML = untrusted;
```

With `require-trusted-types-for 'script'` enforced, that assignment throws a `TypeError`. Nothing
reaches the sink unless it came out of a named policy:

```javascript
// Fixed: one reviewed policy, one place to audit
import DOMPurify from "dompurify";

const policy = window.trustedTypes.createPolicy("app-html", {
  createHTML: (input) => DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: false }),
  // createScriptURL and createScript deliberately omitted: nothing needs them
});

element.innerHTML = policy.createHTML(untrusted);
```

Why this works: it converts an audit problem into a compile-and-runtime problem. Instead of finding
every `innerHTML` in a growing codebase, you review one policy function. Every unreviewed sink
becomes a loud runtime error in development rather than a silent vulnerability in production.

Lock down policy creation so an injected script cannot make its own:

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types app-html dompurify;
```

Without the `trusted-types` allowlist directive, attacker-injected code can call
`trustedTypes.createPolicy` with a pass-through `createHTML` and defeat the whole mechanism.

Two honest limits. First, a policy whose `createHTML` returns its input unchanged provides nothing
— it satisfies the type system and sanitizes nothing, and this is the most common way Trusted Types
gets adopted incorrectly. Second, browser support is uneven outside Chromium; check current support
data before treating it as your only layer. Roll it out report-only the same way you would a CSP.

## Framework notes

- React sets `dangerouslySetInnerHTML` without going through a Trusted Types sink in some versions.
  Verify against your React version rather than assuming it is covered.
- Angular has `@angular/platform-browser` Trusted Types support and its own sanitizer. Its
  `bypassSecurityTrustHtml` is an explicit opt-out and should be treated as a finding wherever the
  input is not provably safe.
- Vue's `v-html` is a raw sink. Trusted Types enforcement will throw there unless the value came
  from a policy.
- Bundlers that inline runtime code (webpack's `eval` devtool options) require `unsafe-eval`. Use a
  non-eval `devtool` setting in production builds rather than weakening the policy.

## Sources

- CSP Level 3 — <https://www.w3.org/TR/CSP3/>
- Trusted Types — <https://w3c.github.io/trusted-types/dist/spec/>
- OWASP CSP Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
- CSP Evaluator — <https://csp-evaluator.withgoogle.com/>
