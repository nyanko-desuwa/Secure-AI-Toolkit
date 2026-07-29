# Common Mistakes

Failures seen repeatedly in identity code, hand-written and generated. Each entry: what it
looks like, why it fails, and the fix that closes it rather than hiding it.

## Salted SHA-256 treated as password storage

```python
digest = hashlib.sha256(salt + password.encode()).hexdigest()
```

The salt does its job - no rainbow table, no shared record between two users with the same
password. It does nothing about speed. A consumer GPU runs SHA-256 at billions of guesses per
second, so a stolen table is cracked at the rate of the password distribution, not the hash.

Fix: Argon2id with real cost parameters, or bcrypt (work factor 10 or more) where Argon2 is
unavailable. See [best-practices.md](best-practices.md#password-hashing-and-peppering). Do not
"strengthen" a fast hash by iterating it yourself; use the KDF that was reviewed for this.

## Login that answers a question nobody asked

```javascript
if (!user) return res.status(404).json({ error: "account not found" });
```

The endpoint now confirms which email addresses hold accounts. That turns a breach dump from
another site into a targeted list, and it makes the later "we do not disclose whether an email
is registered" reset flow pointless.

The subtler variant is timing (CWE-208): the absent-user path returns in 3 ms because no KDF
ran, the present-user path in 90 ms. Uniform text with non-uniform timing is still an oracle.

Fix: one response for every failure, and verify against a dummy hash when the account does not
exist so both paths pay the same cost.

## Per-IP rate limiting called credential stuffing defence

```python
if failures_from_ip(request.remote_addr) > 10:
    return too_many_requests()
```

Credential stuffing is one attempt per account from thousands of addresses. Nothing crosses ten
failures per IP, so nothing trips. Meanwhile a corporate NAT or mobile carrier gateway hits the
limit with legitimate users behind it.

Fix: limit on several dimensions - account, IP, device signal, and global failure rate - and
alert on the aggregate. NIST SP 800-63B-4 §3.2.2 caps consecutive per-account failures; treat
that as a floor, not the control. Check submitted passwords against a breached-password list at
registration and change, since stuffing only works with known credentials.

## Session ID kept across login

```php
$_SESSION['user_id'] = $user->id;
```

The identifier the browser held before authentication still works after it. An attacker who set
that value first - a link with a session parameter, a cookie written from a sibling subdomain,
an XSS on any page in scope - is now inside the victim's account. Session fixation, CWE-384.

Fix: `session_regenerate_id(true)` (or the framework equivalent) before writing the identity,
which destroys the old record instead of leaving it valid. Rotate again on password change and
on any role elevation.

## Logout that only clears the cookie

```javascript
res.clearCookie("sid");
res.redirect("/");
```

The server-side session, or the still-valid JWT, survives. Anyone holding a copy of the token -
from a shared machine, a proxy log, a stolen backup - keeps the account. Same class of bug:
changing a password without terminating other sessions, which is exactly the action a user takes
after suspecting compromise.

Fix: destroy the server-side record, then clear the cookie. For stateless tokens, bump a
per-user `sessions_valid_after` timestamp and reject older tokens, or keep a revocation list.
Offer "sign out everywhere" and run it automatically on password change and MFA change.

## `SameSite=Lax` in place of a CSRF token

```javascript
app.use(session({ cookie: { sameSite: "lax" } }));  // "CSRF handled"
```

`Lax` withholds the cookie on cross-site subresource and form-POST requests, which blocks the
textbook case. It does not cover top-level GET navigations, so any state change reachable by GET
is still exploitable. It does not isolate same-site attackers: a subdomain, a sibling app, or a
same-site open redirect is not cross-site. Browser defaults also differ by version, and some
requests are exempt during a short window after cookie creation.

Fix: keep `SameSite`, and add a synchronizer token or `Origin`/`Sec-Fetch-Site` verification on
every state-changing request. Never route state changes through GET.

## JWT payload read before verification

```javascript
const { role, sub } = jwt.decode(req.headers.authorization.split(" ")[1]);
if (role === "admin") return next();
```

`decode` parses; it does not check a signature. The claims are attacker-supplied JSON. The
neighbouring failure is verifying without pinning: the token's `alg` header selects the
algorithm, so `HS256` signed with the published RSA public key, or `alg: none`, is accepted by
libraries that honour it. Pinning the algorithm but letting `kid`/`jku` point at a URL the
attacker controls has the same result.

Fix: verify with a server-configured key set and a fixed algorithm list, validate `iss`, `aud`,
and expiry, and resolve `kid` only against keys you already trust. See
[examples/README.md](examples/README.md#jwt-algorithm-and-key-confusion).

## Reset token built from data the requester knows

```python
token = hashlib.md5(f"{user.email}{int(time.time())}".encode()).hexdigest()
```

Every input is known or narrow. An attacker requests a reset for the victim, knows the email,
and brute-forces a few thousand candidate timestamps offline. Sequential IDs, incrementing
counters, and `uuid1()` (time and MAC based) fail the same way. `uuid4()` is CSPRNG-backed in
CPython but is a weak habit to teach, because the property people remember is uniqueness, not
unpredictability.

Fix: `secrets.token_urlsafe(32)`, stored hashed, single-use, short expiry, invalidated when a
new one is issued and after use, and every session terminated once the password changes.

## Reset link that logs the user in

```python
if token_valid: login_user(user); return redirect("/settings")
```

The reset link becomes a bearer credential. It sits in mail archives, forwarded threads, and
provider logs, and it usually predates any MFA check. Anyone reading the mailbox - or a shared
inbox, or a support ticket attachment - gets an authenticated session without knowing the
password or the second factor.

Fix: the token authorises exactly one action, setting a new password. Then require a normal
login, including MFA. Do not extend a reset token's lifetime to make support easier.

## Authorization derived from the request

```javascript
const user = await db.user.findUnique({ where: { id: req.body.userId } });
```

Or a header, or a `tenantId` query parameter, or a `role` claim in a token the client can
re-mint. Every one is client input. This is the mechanism behind most "authenticated user reads
another tenant's data" incidents, and it survives review because the code looks like it is doing
a lookup rather than a decision.

Fix: derive the actor from the verified session server-side, and put the tenant and ownership
constraint into the query itself so there is no separate `if` to omit.

## Client-side authorization with a matching server gap

```jsx
{user.isAdmin && <DeleteAllButton />}
```

Hiding the control hides the discovery, not the capability. `DELETE /api/records` still answers
whoever calls it. The same pattern appears as a route guard in the SPA router with no server
check behind it.

Fix: enforce on the server for every endpoint, deny by default, and treat the UI condition as
presentation only.

## Failing open when the identity provider is down

```python
try:
    claims = verify_with_idp(token)
except Exception:
    claims = {"sub": "anonymous", "role": "user"}  # keep the site up
```

Written to survive an outage. The cheapest way to bypass authentication is now to make the IdP
unreachable - or just to send a token that raises during parsing, since the bare `except`
swallows the failure too.

Fix: return 401 or 503 and log it. Cache the JWKS with a sensible TTL so a brief provider blip
does not need a fallback identity at all.

## Wildcard redirect URI matching

```python
if redirect_uri.startswith("https://app.example.test"):
    accept(redirect_uri)
```

`https://app.example.test.attacker.test/` passes. So does an open redirect on the real host, and
a subdomain takeover if the registration allows `*.example.test`. The authorization code, and
sometimes the token, leaves with it.

Fix: exact string comparison against the registered set (RFC 9700 §4.1.3), with the localhost
port exception for native apps only. Keep redirect hosts free of open redirectors.

## Access token in `localStorage`

```javascript
localStorage.setItem("access_token", tokens.access_token);
```

Any script running on the origin reads it - including one arriving through a compromised
dependency. Persisted in the browser profile, it also survives long past the tab.

Fix: for browser sessions, a `__Host-` prefixed `HttpOnly`, `Secure` cookie plus CSRF defence,
with the token exchange done by a backend. Where a token must reach JavaScript, keep it in
memory only, keep its lifetime in minutes, and rely on rotating refresh tokens with reuse
detection.

## Impersonation implemented as a variable assignment

```python
session["user_id"] = target_user_id  # support mode
```

The audit trail now says the customer did it. There is no reason recorded, no expiry, no step-up,
and no way to answer "which staff member opened this account last Tuesday".

Fix: store operator and effective subject as separate fields, require recent step-up
authentication and a stated reason, bound the duration, exclude the ability to escalate further,
and log start, sensitive actions, and end with both identities.

## MFA enforced at login and nowhere else

Password change, email change, MFA enrolment and removal, API key creation, and payout details
all accept a session that authenticated hours ago. A stolen session cookie converts into
permanent access by removing MFA and swapping the recovery email.

Fix: step-up on sensitive actions - require authentication within a recent window, and re-prompt
for a second factor. Notify the user on every authenticator or contact-address change, and send
that notice to the previous address as well.
