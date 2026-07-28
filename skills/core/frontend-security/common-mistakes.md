# Common Mistakes

What it looks like, why it fails, the fix, and why the fix holds. These are the fixes developers
reach for on their own, which is why they need heading off.

## Escaping by hand instead of using a text sink

```javascript
function escape(s) {
  return s.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
el.innerHTML = `<div title="${escape(name)}">${escape(name)}</div>`;
```

The function covers HTML body context and nothing else. Inside the `title` attribute, a `"` closes
it and `" onmouseover=alert(1) x="` executes. Quote and backtick are missing, and the ampersand is
not escaped first so double-encoding bugs follow.

Fix: `textContent` for text, `setAttribute` for attributes, and no HTML string. Why it works: there
is no parser to escape for. A correct escaper needs a different rule per context — body, attribute,
URL, CSS, JS — and picking the right one at every call site is the failure mode.

## `.includes()` or `.startsWith()` for origin and URL checks

```javascript
if (event.origin.includes("partner.example.com")) handle(event.data);
if (target.startsWith("https://app.example.com")) location.assign(target);
```

`https://partner.example.com.attacker-site.test` contains the string. `https://app.example.com.attacker-site.test`
starts with it. Both checks pass and both hand control to the attacker.

Fix: exact string equality for `event.origin`, and `new URL(...).origin` comparison for URLs. Why it
works: the origin is a normalized, canonical value — scheme, host, port — so there is no substring
ambiguity left to exploit. Substring checks test for a name appearing somewhere in a string an
attacker fully controls.

## Sanitizing on save instead of on render

```javascript
await db.comments.insert({ body: DOMPurify.sanitize(req.body.body) });
```

The stored value is now trusted by everyone. A second consumer with a different renderer — an
email template, a mobile client, an export to PDF — gets HTML that was sanitized for a config it
does not share. Worse, sanitizer updates that fix a bypass do not reach rows already written.

Fix: store the original, sanitize at each render boundary with a config for that context. Why it
works: the control sits next to the sink it protects, so it matches the context and it re-runs after
a library upgrade.

## CSP added as the XSS fix

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'";
```

Two problems compound. `unsafe-inline` permits the injected script the policy was added to stop, so
the header is decorative. And treating CSP as the fix leaves the `innerHTML` sink in place, so any
gap in the policy — a JSONP endpoint on an allowed host, a browser that ignores a directive — is a
live vulnerability again.

Fix: fix the sink, then add a nonce-based CSP as a second layer. Why it works: the sink fix stops
the injection and the CSP contains whatever the next sink misses. Report a missing CSP as a missing
mitigation paired with the XSS it would have contained, not as a finding on its own — otherwise it
gets deprioritized and ignored.

## `unsafe-eval` added to make a library work

A charting or templating dependency throws under CSP, so `unsafe-eval` goes into `script-src` and
the build turns green.

That re-enables `eval`, `new Function`, and string timers for the whole origin, which is most of the
DOM XSS escalation path the policy was meant to block.

Fix: check whether the library ships a CSP-safe or pre-compiled build — most template engines do,
Vue and Angular both have runtime-only versions that need no `eval`. If none exists, isolate the
library in a sandboxed iframe with its own policy and a narrow `postMessage` contract. Why it works:
the relaxation is scoped to a document that holds no session and no DOM you care about, instead of
to the origin.

## `sessionStorage` chosen because `localStorage` is "insecure"

```javascript
sessionStorage.setItem("access_token", token);
```

The two differ only in lifetime. Both are readable by every script on the origin, so an XSS payload
or a compromised dependency reads the token identically. The tab-close behaviour is a UX property,
not a security one.

Fix: an `HttpOnly`, `Secure` cookie with an intentional `SameSite`, plus CSRF protection on
state-changing requests. Why it works: `HttpOnly` removes the value from the DOM API surface
entirely, so script running in the origin cannot read it. State the tradeoff honestly — this bounds
credential theft, it does not stop XSS from acting as the user while the page is open.

## Route guards treated as authorization

```typescript
if (!user.isAdmin) return <Navigate to="/" />;
```

The check runs in code the user controls. Bypassing it takes a devtools breakpoint, a modified
bundle, or simply calling the API directly — the endpoint is in the network tab.

Fix: enforce on the server for every endpoint; keep the guard for navigation only. Why it works: the
server is the only place where the decision cannot be edited by the person it applies to. Hiding a
button is a UX choice; the API is the boundary.

## Client-side validation counted as input validation

```javascript
<input type="email" required maxLength={254} />
```

Attributes constrain the form, not the request. `curl` sends whatever it likes.

Fix: keep the client validation for feedback, and validate again server-side with a schema that
rejects unknown fields. Why it works: two audiences, two purposes. The client one is for the user,
the server one is the control.

## `rel="noreferrer"` without `noopener`, or neither

```html
<a href="https://partner.example.com" target="_blank">Partner</a>
```

The opened page gets a `window.opener` reference and can navigate your tab with
`opener.location = "https://phishing.attacker-site.test"` while the user is looking at the new tab.
Modern browsers imply `noopener` for `target="_blank"`, but that is a default you inherit rather
than a control you set, and it does not apply to `window.open`.

Fix: `rel="noopener noreferrer"` on the anchor, and `window.open(url, "_blank", "noopener,noreferrer")`
in script. Why it works: the reference is never created, so there is nothing to navigate through.
`noreferrer` alone happens to imply `noopener` in current browsers; writing both is explicit and
survives a browser policy change.

## Trusting your own API response

```javascript
const { html } = await res.json();
container.innerHTML = html;
```

"It comes from our backend" means it comes from whatever any user typed into the backend. The API is
a transport, not a sanitizer.

Fix: sanitize or render as text at the client boundary, regardless of source. Why it works: the
control is placed where the untrusted data meets the dangerous sink, which is the only place that
knows the rendering context.

## `X-Frame-Options: ALLOW-FROM`

```nginx
add_header X-Frame-Options "ALLOW-FROM https://partner.example.com";
```

`ALLOW-FROM` was never implemented by Chrome or Safari and is obsolete. Setting it means those
browsers see an unrecognized value and apply no framing restriction at all — the page is fully
frameable, which is the opposite of the intent.

Fix: `Content-Security-Policy: frame-ancestors https://partner.example.com`, with
`X-Frame-Options: DENY` only when no framing is allowed at all. Why it works: `frame-ancestors` is
the specified mechanism, supports a list of origins, and is honoured by current browsers. When both
headers are present and a browser supports CSP, `frame-ancestors` wins.

## `SameSite=None` set to fix a broken login

A cross-origin flow fails, someone sets `SameSite=None` on the session cookie, and it works again.

`None` re-enables the exact cross-site attachment that CSRF depends on, on every request from every
site.

Fix: confirm the flow actually needs cross-site cookie delivery. Most do not — an OAuth redirect
lands on your own origin, so `Lax` is enough. Where `None` is genuinely required, it demands
`Secure`, and every state-changing endpoint needs an explicit CSRF token. Why it works: the cookie
attribute is a mitigation, so removing it means the primary control has to be present.

## A regex denylist for `javascript:`

```javascript
if (/^javascript:/i.test(url)) return "#";
```

`java\tscript:`, `java&#09;script:`, a leading newline, `%6a%61...`, and `data:text/html;base64,...`
all bypass it. The list of encodings a browser accepts is longer than the list you thought of.

Fix: parse with `new URL()` and allowlist `url.protocol`. Why it works: normalization happens before
the check, so every encoding of the same scheme collapses to one comparable value. Denylists
enumerate what you remembered; allowlists enumerate what you support.

## Reusing a CSP nonce

```javascript
const NONCE = "abc123";   // module scope, one value for the process lifetime
```

A nonce that appears in more than one response is guessable from any earlier response. An attacker
fetches a page, reads the nonce, and includes it in the injected script tag.

Fix: generate per response from a CSPRNG — `crypto.randomBytes(16).toString("base64")`. Why it works:
unpredictability is the entire mechanism. Also avoid deriving it from a timestamp, a request
counter, or a session ID for the same reason.

## Source maps shipped to production without checking contents

`npm run build` emits `.map` files, they get uploaded, and the original TypeScript — including
comments, internal endpoint names, and any value inlined at build time — is publicly readable.

Fix: either do not publish maps, or upload them to the error tracker with authentication and exclude
them from the public bundle. Separately, treat anything inlined by the bundler as public: a
`VITE_`/`NEXT_PUBLIC_` variable is in the JavaScript whether a map exists or not. Why it works: it
separates debugging access from public access, and it stops the build tool from being a
secret-exfiltration path.

## Assuming the header you wrote is the header that ships

Source sets a good CSP. A CDN, a reverse proxy, a WAF, or framework middleware overwrites or drops
it, and nobody checks.

Fix: `curl -sI https://app.example.com | grep -i -e content-security -e x-frame -e strict-transport`
against the real origin, and assert on headers in an integration test. Why it works: it verifies the
response the browser receives rather than the intent expressed in a config file. Until you have run
it, say the deployed configuration is unverified.
