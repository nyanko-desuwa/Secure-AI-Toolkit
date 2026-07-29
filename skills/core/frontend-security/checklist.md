# Frontend Security Checklist

Run the sections that match the change. Mark every item pass, fail, or not applicable with a
reason. Do not claim a deployed control from source inspection alone.

## Data flow and XSS - A05 · ASVS V1, V3 · CWE-79

- [ ] Searched for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`,
      `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `bypassSecurityTrust*`, `eval`, `new Function`,
      and string-based timers
- [ ] Traced every candidate sink to its source, including URL hash, query, referrer, storage,
      `window.name`, `postMessage`, and API responses
- [ ] Text uses framework interpolation or `textContent`, not HTML construction
- [ ] HTML that must remain HTML is sanitized with a pinned library and an explicit allowlist
- [ ] Sanitizer output is used only in the context it was configured for
- [ ] URL values are parsed and scheme-checked before assignment to `href`, `src`, `action`, or
      `window.open`
- [ ] No user input reaches event-handler attributes, attribute names, CSS interpolation, or an
      eval-family API
- [ ] React `dangerouslySetInnerHTML`, Vue `v-html`, and Svelte `{@html}` have a documented reason,
      sanitizer, and regression tests
- [ ] No client-side validation is treated as server authorization or input validation

## CSP and Trusted Types - A02 · ASVS V3, V13 · CWE-79

- [ ] CSP is sent as an HTTP response header on the real origin
- [ ] `script-src` uses per-response nonces or hashes; no broad `unsafe-inline`
- [ ] `unsafe-eval` is absent unless an assessed legacy dependency requires it
- [ ] `object-src 'none'` and `base-uri 'none'` are present
- [ ] `frame-ancestors` names allowed parents or is `'none'`
- [ ] `connect-src`, `img-src`, `style-src`, and `font-src` are explicit and minimal
- [ ] `strict-dynamic` is used only with a nonce/hash and its browser fallback is understood
- [ ] Report-only policy was tested before enforcement, and reports contain no sensitive data
- [ ] `require-trusted-types-for 'script'` is enabled where browser support and dependencies allow
- [ ] Trusted Types policies are small, reviewed, and do not return arbitrary strings
- [ ] CSP is not used as the only XSS fix; sinks remain safe without it

## Cookies, tokens, and CSRF - A02, A07 · ASVS V3, V6, V7 · CWE-352, CWE-1004, CWE-1275

- [ ] Tokens are not in `localStorage`, `sessionStorage`, URL parameters, HTML, or the JS bundle
- [ ] Session cookies are `HttpOnly`, `Secure`, and have an intentional `SameSite` value
- [ ] Cross-site cookie use is justified before choosing `SameSite=None`
- [ ] Cookie `Domain` is omitted unless subdomain sharing is required
- [ ] State-changing cookie-authenticated requests have a CSRF token or equivalent server check
- [ ] CSRF token is not accepted solely from a cookie the attacker can set
- [ ] CORS does not use wildcard origin with credentials
- [ ] Logout and password-change behaviour invalidates the server-side session
- [ ] Access tokens have bounded lifetime and are refreshed server-side or through a reviewed flow
- [ ] Client route guards are presentation only; API authorization is server-side

## Navigation and windows - A01, A05 · ASVS V2, V3 · CWE-601

- [ ] Redirect targets are mapped to known paths or same-origin URLs
- [ ] `javascript:`, `data:`, and unexpected schemes are rejected
- [ ] `window.open` uses a safe target and `noopener,noreferrer`
- [ ] External links use `rel="noopener noreferrer"` when opening a new context
- [ ] `postMessage` sends to an exact target origin, not `*`
- [ ] Message handlers check `event.origin` and, where needed, `event.source`
- [ ] Message data is schema-validated before use
- [ ] `window.name` is treated as attacker-controlled

## Clickjacking and headers - A02 · ASVS V3, V13 · CWE-1021, CWE-346

- [ ] `frame-ancestors` or `X-Frame-Options` prevents untrusted framing
- [ ] `X-Content-Type-Options: nosniff` is set
- [ ] `Referrer-Policy` does not send tokens or sensitive paths cross-origin
- [ ] HSTS is enabled only after HTTPS is correct, with an intentional scope
- [ ] Permissions-Policy disables unused powerful browser features
- [ ] CORS allowed origins are exact and reviewed
- [ ] Header values are set by a trusted server layer, not from request input

## Third-party code and assets - A03 · ASVS V3, V13, V15 · CWE-353

- [ ] Third-party scripts are minimized and pinned to an immutable version or digest
- [ ] Cross-origin scripts use SRI `integrity` and `crossorigin="anonymous"`
- [ ] A trusted CSP nonce is applied to approved scripts
- [ ] Dependency changes are reviewed for new DOM sinks and network destinations
- [ ] Source maps do not publish secrets, private source, or embedded environment values
- [ ] `postMessage` integrations document their origin and message schema
- [ ] An externally controlled CDN is not treated as a security boundary

## Prototype pollution and data handling - A05 · ASVS V2, V15 · CWE-1321

- [ ] Deep merge, query-string, and object-path libraries are pinned and current
- [ ] Untrusted keys such as `__proto__`, `constructor`, and `prototype` are rejected where
      object paths are accepted
- [ ] Parsed JSON is schema-validated and unknown properties are rejected where appropriate
- [ ] Configuration objects use `Object.create(null)` or safe maps when keys are untrusted
- [ ] Client-side state is not assumed to be trusted when sent back to the server

## Verification before return

- [ ] Tests cover literal text, HTML, URL schemes, `postMessage` origins, and redirect targets
- [ ] Browser tests exercise the deployed or production-equivalent CSP
- [ ] `curl -I` against the real origin confirms headers and cookie attributes
- [ ] A DOM XSS scanner or SAST rule ran, with results reported honestly
- [ ] No real credentials, personal data, or live domains were added to examples or tests
- [ ] Any unverifiable CDN, proxy, browser, or runtime behaviour is stated plainly
