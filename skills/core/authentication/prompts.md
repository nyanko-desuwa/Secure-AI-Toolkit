# Prompt Examples

Prompts that produce findings instead of a recital of auth theory. Each one bounds the scope,
names the standard, and says what the answer should look like.

## Review the login path

```
Read the login handler and everything it calls. Check: password verification algorithm and
parameters, whether the error response and timing differ between "no such user" and "wrong
password", what throttling exists and whether it survives one attempt per account from
rotating IPs, and whether the session identifier changes after successful login.
Cite A07:2025 and ASVS V6/V7 per finding.
```

Why it works: names the four things that actually go wrong in a login handler, so the answer
cannot be a summary. The throttling clause specifically asks about distributed stuffing, which
a per-account limit does not cover.

## Trace session invalidation

```
Trace what happens to existing sessions on logout, password change, MFA enrolment change, and
password reset. For each, tell me whether server-side state is destroyed or only the client
cookie is cleared. If sessions are JWTs, tell me the revocation window in seconds.
```

Four events, because teams handle logout and miss the other three. Asking for the window in
seconds forces an honest answer about JWT revocation rather than "tokens are short-lived".

## Audit the password reset flow

```
Threat model the password reset flow. Assume the attacker knows the victim's email address and
their account creation date. Cover: token entropy and its source, whether the token is stored
hashed, single-use enforcement, expiry, whether the response differs for a registered and an
unregistered address, and whether other sessions survive the reset.
```

The stated starting knowledge is what makes this specific. Creation date matters because
timestamp-seeded tokens are the classic guessable-token bug.

## Check JWT verification

```
Find every place a JWT is decoded or verified. For each: is the algorithm pinned server-side,
are issuer and audience checked, is expiry checked, and is any claim read before verification?
Report anything that calls a decode function without a signature check. Cite ASVS V9 and CWE-347.
```

"Read before verification" catches the `jwt.decode` used for logging or routing, which is the
version of algorithm confusion that survives in otherwise careful code.

## Review an OAuth integration

```
Review the OAuth2 client integration against RFC 9700. Check the grant type, whether PKCE
S256 is used, whether state is generated per request and verified on callback, whether the
redirect URI is registered for exact match, and where the resulting tokens are stored in the
browser.
```

## Design an authorization model

```
I need per-document sharing with roles at the workspace level and per-document overrides.
Before I write code: RBAC, ABAC, or ReBAC? Show me how "can user X read document Y" would be
answered in each, and which one I can still audit in two years.
```

The auditability clause is the point. Every model can express the rules; they differ in
whether anyone can explain the result later.

## Verify before returning

```
Run skills/core/authentication/checklist.md against this change. Mark each item pass, fail, or
not applicable with a reason. Do not mark anything pass that you have not read the code for.
```

## Challenge a control

```
You said to rotate refresh tokens with reuse detection. Our mobile client retries on network
timeout, so it will replay a refresh token legitimately and get the whole family revoked.
What should win, and what breaks either way?
```

Real conflicts are normal. See [troubleshooting.md](troubleshooting.md).

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my auth secure?" | No scope. Produces a lecture, not findings |
| "Add authentication to this app" | Skips the model decision. You get whatever the model saw most often in training |
| "Make the login OWASP compliant" | There is no Top 10 certificate. Ask for named controls |
| "Use JWT for sessions" | Prescribes the mechanism before the requirement. Ask what logout must do first |
| "Add MFA" | Without naming the factor you get SMS, the weakest permitted option |
| "Hash the passwords" | Underspecified enough that SHA-256 satisfies it. Name the KDF and parameters |
| "Fix all the auth vulnerabilities" | Invites a speculative rewrite of working credential code, which is the worst place for one |
