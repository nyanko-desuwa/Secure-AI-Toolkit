# Troubleshooting

What to do when a control does not apply cleanly, or when you cannot confirm it.

## The CSP breaks the application

Do not delete the policy and do not add `unsafe-inline`. Work in this order:

1. Switch to `Content-Security-Policy-Report-Only` so nothing is blocked while you collect data.
2. Read the violation reports. Each names the directive, the blocked URI, and the source line.
3. Group the violations. Inline scripts need a nonce. Third-party hosts need an explicit source.
   `eval` needs a different build of the dependency.
4. Fix the causes, confirm the report stream is empty under real traffic, then enforce.

Report-only mode is the whole point of the two-header design. Shipping an enforced policy you have
not observed is how a policy gets rolled back permanently after one incident.

## A dependency needs `unsafe-eval` and there is no CSP-safe build

State the tradeoff rather than silently relaxing the origin's policy. Options in order of
preference:

1. Replace the dependency. Check whether the maintained alternative is CSP-safe first.
2. Move to a pre-compiled or runtime-only build. Most template engines, Vue, and Angular offer one.
3. Isolate the library in a sandboxed iframe on a separate origin with its own relaxed policy, and
   talk to it over `postMessage` with a validated schema.
4. If none of the above is possible, add `unsafe-eval` and record it: which dependency, which
   version, who accepted it, and what would remove it.

Option 4 is a documented exception, not a fix. Do not present it as one.

## The token has to be readable by JavaScript

Sometimes the API is on another origin, cookies are impractical, or a third-party SDK requires the
raw token. Say what that costs and bound it:

- Keep the token in a module-scoped variable, not in `localStorage`. It dies with the page and is
  not readable from another tab or after a reload.
- Keep the refresh token in an `HttpOnly` cookie, and let the access token be short-lived.
- Bind the token to a short lifetime, and to the client where the API supports sender-constrained
  tokens.
- Accept that XSS still means the attacker acts as the user for the page's lifetime. There is no
  client-side storage that survives script execution in the same origin.

Do not claim a variable is "safe from XSS". It is less exposed than storage, which is a real
difference, and it is not protection.

## CSRF tokens are impossible in this architecture

If the client cannot obtain a token — a third-party embed, a legacy form, a device with no session —
fall back in this order:

1. `SameSite=Lax` or `Strict` on the session cookie, plus an `Origin`/`Sec-Fetch-Site` check on
   every state-changing request server-side.
2. Move authentication to an `Authorization` header, which browsers do not attach automatically, so
   CSRF does not apply.
3. Re-authenticate for the specific sensitive action.

`SameSite` alone is a mitigation, not a control. It does not protect against a same-site attacker on
a sibling subdomain, and older browsers ignore it. Name that gap when you rely on it.

## You cannot tell whether the header is actually deployed

Reading source proves intent, not delivery. A CDN, a WAF, an ingress controller, or framework
middleware can add, replace, or drop a header after your code runs.

Verify against the real origin:

```bash
curl -sI https://app.example.com \
  | grep -i -e content-security-policy -e x-frame-options -e strict-transport-security \
            -e x-content-type-options -e referrer-policy
```

If you have no access to the deployed environment, say so explicitly: "the source sets a nonce-based
CSP; the deployed header is unverified". An implied pass is worse than a stated gap.

## Sanitized output still looks wrong, or the sanitizer strips needed markup

The config is fitted to the wrong context. Check three things:

- Is the output going where the config assumed? A config for a comment body is wrong for an SVG, an
  attribute, or a `srcdoc`.
- Are you sanitizing twice? Chained sanitizers with different configs produce output neither one
  validated.
- Is a custom hook re-adding what the allowlist removed? A hook that restores `target` or a
  `data-` attribute can reopen the hole the allowlist closed.

Widen the allowlist one tag or attribute at a time, with a test per addition. Never switch to a
denylist to make an editor work.

## The framework escape hatch is genuinely required

Rich-text editors, email previews, and CMS content sometimes need real HTML. Do not remove the
requirement; constrain it:

- One wrapper component that sanitizes, used everywhere. No raw `dangerouslySetInnerHTML`,
  `v-html`, or `{@html}` outside it.
- A lint rule that fails the build on direct use of the escape hatch.
- Tests with the payloads your product actually accepts, including the ones that previously broke.
- A comment naming who approved it and why.

Why this holds: the dangerous call exists once and is reviewed, instead of appearing in forty
places where only some are sanitized.

## Two standards or two reviewers disagree

Implement the more restrictive option and say you did. ASVS gives testable requirements; the Top 10
gives a risk ranking for reporting — they rarely conflict once you separate those roles.

Where a project constraint genuinely conflicts with a control, report the conflict rather than
resolving it silently: current behaviour, what the secure version changes, who breaks, and the
migration path. A change to auth or cookie scope is not a minor decision to make alone.

## You cannot tell if a sink is reachable

Report it with the uncertainty attached. "`innerHTML` at `src/widgets/Banner.tsx:42`, fed from a
prop; I could not find a caller that passes user data, so reachability is unconfirmed" is useful.
"Critical XSS" without tracing the source is noise, and noise gets checklists ignored.

Rank the unconfirmed finding as a code smell and say what would confirm it.

## Trusted Types is not supported in a target browser

Trusted Types support is uneven outside Chromium. Treat it as a hardening layer for the browsers
that enforce it, not the only control.

- Keep the per-sink fixes. They work everywhere.
- Ship the `require-trusted-types-for 'script'` directive anyway; browsers that do not support it
  ignore the directive rather than failing.
- Use report-only first, because a violation in a dependency becomes a runtime error once enforced.
- Check current support data before claiming coverage. Do not quote a support matrix from memory.

## The vulnerable code is in a third-party bundle

You cannot patch it in place. In order:

1. Update. Check the changelog for the sink, not just the version number.
2. Constrain it with CSP and Trusted Types so the sink throws rather than executes.
3. Stop passing untrusted data into it — validate at your own boundary before the call.
4. Replace or fork it, and say what the temporary exposure is until then.

Record the exposure window. "Mitigated by CSP, dependency upgrade pending" is an honest state.

## A checklist item does not apply

Write the reason. "No CSP section: this change adds a unit test only" is complete. An unexplained
skip is indistinguishable from an oversight, and one of those in a report devalues the rest.
