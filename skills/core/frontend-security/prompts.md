# Prompt Examples

Prompts that produce findings instead of a lecture. Each one bounds the input, names the standard,
and states the shape of the answer. Vague prompts get a recital of the OWASP list back.

## Find DOM XSS by sink, then by source

```
Grep src/ for these sinks: innerHTML, outerHTML, insertAdjacentHTML, document.write, srcdoc,
dangerouslySetInnerHTML, v-html, {@html}, bypassSecurityTrust, eval, new Function, and
string-argument setTimeout/setInterval.

For each hit, trace backwards to the source. Report file:line, the sink, the source, the
exploitation URL or payload, the CWE, and the fixed code. Skip any sink fed only by literals and
say how many you skipped.
```

Why it works: the sink list is finite and greppable, so the model searches instead of guessing. The
skip instruction stops the output filling with `innerHTML = "<b>Loading</b>"`.

## Audit the URL sinks specifically

```
Find every assignment to href, src, action, formaction, location, location.href, and every
window.open call in src/. For each, tell me whether the value can be attacker-controlled and
whether a javascript: or data: URL would reach it. Give me the scheme check you would add.
```

URL sinks get missed because they are not called `innerHTML`. Asking for them separately is worth
the extra prompt.

## Break the CSP before fixing it

```
Here is our Content-Security-Policy header:

  <paste header>

Tell me whether it stops reflected XSS. If it does not, give me the concrete bypass - the exact
payload or the exact host on the allowlist that hosts a JSONP endpoint or an unsafe framework
build. Then give me the nonce-based replacement with strict-dynamic, object-src, and base-uri.
```

Asking for the bypass first is the difference between a real review and a directive checklist. A
policy with `unsafe-inline` or a wide CDN allowlist reads as strict and stops nothing.

## Compare token storage honestly

```
Our SPA keeps the access token in localStorage. Do not just tell me that is bad. Walk me through
what changes if we move to an HttpOnly, Secure, SameSite cookie: which XSS impact goes away, which
does not, what CSRF work it adds, and what breaks if the API is on a different origin.
```

Naming the refusal ("do not just tell me") avoids the reflex answer and forces the tradeoff, which
is the part the reader actually needs.

## Review the framework escape hatch

```
Find every dangerouslySetInnerHTML, v-html, and {@html} in this repo. For each: is the input
sanitized, with which library and config, and is that config right for the context it renders in?
Where sanitization is missing, give me the wrapper component I should route it through instead.
```

Asking for the wrapper rather than a per-site fix produces the one reviewed call site instead of
forty scattered ones.

## Review postMessage both directions

```
Review every window.postMessage call and every message event listener in src/. For each: is the
target origin exact or '*'? Does the handler check event.origin against an allowlist before
touching event.data? Is event.data schema-validated? Show me the exploit for each gap.
```

Both directions matter and reviewers usually check only the listener. The send side leaks data to
whatever origin the frame navigated to.

## Header review against the deployed origin

```
Read our nginx config and Express middleware, list the security headers we intend to send, then
tell me which ones you cannot confirm are actually delivered. Give me the curl command to verify
each one against https://app.example.com.
```

Explicitly asking what cannot be confirmed is how you avoid a report that implies the headers are
live when a CDN is overwriting them.

## Redirect and open-redirect audit

```
Find every place we redirect based on a query parameter, a hash, or a stored value. For each, show
me whether an absolute external URL, a protocol-relative //evil.example URL, or a javascript: URL
survives the current check. Then give me the allowlist-based version.
```

Naming the three bypass shapes gets them tested. Left open, the answer is usually "it checks for
`http://`, looks fine".

## Third-party script review

```
List every third-party script tag and dynamically injected script in this app. For each: is the
version pinned, is there an SRI hash, is crossorigin set, and what would that vendor be able to do
if their CDN were compromised tomorrow? Rank by blast radius.
```

The blast-radius framing produces a prioritised list instead of "add SRI everywhere", which nobody
does in one sitting.

## Verify before returning

```
Run skills/core/frontend-security/checklist.md against this diff. Mark each item pass, fail, or not
applicable with a one-line reason. Do not mark anything pass that you have not actually checked in
the code, and list separately anything that needs the deployed environment to confirm.
```

The last sentence is load-bearing. Without it you get a wall of checkmarks including the headers
nobody looked at.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my frontend secure?" | No scope, no sink list. Produces a summary of the OWASP Top 10 |
| "Add a CSP" | Yields a policy nobody tested. Ask for report-only first, then the violations |
| "Sanitize all user input" | Sanitizing on input corrupts data and still fails at the sink. Encode per sink |
| "Fix the XSS" | Without the source traced, you get `escape()` added in the wrong layer |
| "Make it XSS-proof" | Invites a regex denylist. Ask for the sink-appropriate control instead |
| "Is localStorage safe?" | Yes/no question with a tradeoff answer. Ask what changes if you move the token |
| "Validate on the client too" | Fine for UX, never a control. Say which one you are asking for |
| "Add security headers" | Produces a copy-pasted block including headers that do nothing. Ask what each blocks |
