# Authentication Best Practices

Each control maps to OWASP Top 10 2025, an ASVS chapter, and a CWE where one applies.
The code is runnable in the named ecosystem. Replace adapter calls with the project's tested
libraries; do not weaken the control to fit a different API.

## Password hashing and peppering

`A07:2025` · ASVS V6, V11 · CWE-256

A general-purpose hash is fast by design. A salt stops precomputed rainbow tables, not a GPU
trying billions of guesses. Argon2id is the default. Use bcrypt only where Argon2 is not
available, with a work factor of at least 10 and its 72-byte input limit. A pepper helps only
if it is separate from the database; it creates an operational password-reset problem on
rotation.

```python
# Vulnerable: fast hash; a salt would not make this slow
import hashlib
stored = hashlib.sha256(password.encode()).hexdigest()

# Fixed: argon2-cffi uses Argon2id; cost values are explicit and should be benchmarked
from argon2 import PasswordHasher, Type

ph = PasswordHasher(memory_cost=19_456, time_cost=2, parallelism=1, type=Type.ID)
stored = ph.hash(password)                 # includes a unique random salt
valid = ph.verify(stored, password)
```

Why this works: the memory-hard KDF makes each offline guess expensive. The salt makes two
users with the same password produce different records. The wrong fix is `sha256(salt +
password)`: the salt is useful, but SHA-256 still lets an attacker run guesses at hardware
speed. A pepper belongs in a vault/HSM and must not be pasted into source.

## Uniform login and distributed throttling

`A07:2025` · ASVS V6, V16 · CWE-204, CWE-208, CWE-307

Do not return `no such user` for one branch and `wrong password` for another. Verify against a
dummy Argon2 hash when the account is absent, then apply limits that cannot be bypassed by
rotating source IPs. Per-account limits alone can lock out victims; per-IP limits alone are
useless against a botnet.

```typescript
// Vulnerable: enumeration oracle and one-IP-only throttling
if (!user) return res.status(404).json({ error: "no such user" });
if (!await bcrypt.compare(password, user.hash)) return res.status(401).json({ error: "wrong password" });
if (failedByIp(req.ip) > 10) return res.sendStatus(429);

// Fixed: same public response; account + IP + device/global controls are in the limiter
const candidate = user?.passwordHash ?? DUMMY_ARGON2_HASH;
const passwordOK = await argon2.verify(candidate, password);
const allowed = await limiter.allow({
  account: normalize(email), ip: req.ip, device: deviceFingerprint(req),
});
if (!allowed || !user || !passwordOK) {
  audit("login_failure", { account: normalize(email), ip: req.ip });
  return res.status(401).json({ error: "invalid_credentials" });
}
```

Why this works: both existence branches perform a KDF operation and return the same response.
The limiter can correlate a low-rate attack spread over many IPs by account and device signals.
Do not use a permanent CAPTCHA as the only throttle; it is expensive for real users and often
solvable at scale.

## Server-side sessions and rotation

`A07:2025` · ASVS V7 · CWE-384, CWE-613

A server-side session makes logout and password-change invalidation immediate. The cookie is
only an opaque lookup key. Rotate it after login and every privilege change. Set both an idle
and an absolute timeout on the server.

```javascript
// Vulnerable: attacker fixes the anonymous ID; login keeps it
req.session.userId = user.id;
res.cookie("sid", req.sessionID); // old ID remains valid

// Fixed: destroy the pre-auth session, issue a new ID, and bind server state
await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
req.session.userId = user.id;
req.session.authenticatedAt = Date.now();
req.session.lastSeenAt = Date.now();
res.cookie("__Host-sid", req.sessionID, {
  httpOnly: true, secure: true, sameSite: "lax", path: "/",
});
```

Why this works: a value known before authentication has no authority after it. The tempting
wrong fix is a random-looking client-side session ID without server state; it cannot be
revoked on logout or password change. `SameSite=Lax` reduces some cross-site cookie sends but
is not CSRF protection; use a synchronizer token or equivalent on state changes.

## JWT verification and its honest revocation limit

`A07:2025` · ASVS V9, V11 · CWE-347

JWT claims are attacker input until the signature and all relevant claims pass validation.
Pin the algorithm in server configuration. Pinning only `algorithms: ['RS256']` is not enough
if the library lets a token's `kid`, `jku`, or `x5u` select an attacker-controlled key.

```javascript
// Vulnerable: header chooses the algorithm and key; claims are trusted after decode
const claims = jwt.decode(token);
if (claims.role === "admin") allow();

// Fixed: trusted issuer/JWKS, pinned algorithm, issuer/audience and time checks
const claims = await jwtVerify(token, trustedJwks, {
  algorithms: ["RS256"],
  issuer: "https://id.example.test",
  audience: "orders-api",
  clockTolerance: 5,
});
if (!claims.payload.scope?.split(" ").includes("orders:read")) deny();
```

Why this works: the verifier chooses the key set and algorithm, then checks the claims before
using them. The classic confusion attack changes `alg` from RS256 to HS256 and signs with the
public RSA key as an HMAC secret; a verifier accepting both key types treats a public key as a
shared secret. `none` is the same class of failure. A JWT still cannot be revoked instantly
without checking server state. Use short access-token lifetimes, or keep a denylist/session
record when logout must take effect now.

## Refresh rotation with reuse detection

`A07:2025` · ASVS V9, V10 · CWE-384

Store a hash of each refresh token and its family. On use, atomically mark it spent and issue
the replacement. Seeing a spent token means theft or a race: revoke the whole family rather
than guessing which client is honest.

```python
# Fixed: one-use family state; transaction/row lock is required in real storage
async def refresh(raw: str):
    token = await db.refresh_tokens.lock_by_hash(sha256(raw))
    if token is None or token.expires_at < now(): raise Unauthorized()
    if token.used_at is not None:
        await db.revoke_family(token.family_id)
        raise Unauthorized("refresh_reuse")
    await db.mark_used(token.id, now())
    replacement = secrets.token_urlsafe(48)
    await db.insert_refresh(sha256(replacement), token.family_id, token.user_id)
    return issue_short_access_token(token.user_id), replacement
```

Why this works: concurrent use cannot silently create two live descendants if the lookup and
mark are atomic. Expiring a token alone does not detect reuse during its lifetime.

## OAuth2/OIDC code + PKCE

`A07:2025` · ASVS V10 · CWE-601

Use authorization code with PKCE `S256`, bind the browser transaction with `state`, and for
OIDC validate `nonce`, issuer, audience, and the code exchange. Register exact redirect URIs.
Do not use implicit or resource-owner password grants. The RFC 9700 reference in this skill
contains the current normative wording.

```typescript
// Fixed: transaction-bound values; callback accepts only the exact registered redirect
const verifier = base64url(randomBytes(32));
const challenge = base64url(sha256(verifier));
const state = base64url(randomBytes(32));
await session.save({ state, verifier, nonce });
redirect(authEndpoint, { response_type: "code", code_challenge: challenge,
  code_challenge_method: "S256", state, nonce, redirect_uri: REGISTERED_URI });

if (!timingSafeEqual(Buffer.from(req.query.state), Buffer.from(saved.state))) throw Unauthorized();
const tokens = await oauth.exchangeCode(req.query.code, saved.verifier,
  REGISTERED_URI); // server-side exchange; code is one-use and short-lived
```

Why this works: an intercepted code is useless without the verifier generated by this browser
transaction. `state` blocks login CSRF; `nonce` binds the OIDC ID token. Never solve a redirect
mismatch with `startsWith()` or `*.example.com`: wildcard and open-redirect combinations are
how codes leave the trust boundary.

## MFA, recovery, and step-up

`A07:2025` · ASVS V6 · NIST SP 800-63B-4 §§2, 3.1.3, 3.2.5, 4.2 · CWE-308

Prefer WebAuthn/passkeys because verifier name binding resists phishing. TOTP is useful but
manual codes are not phishing-resistant. SMS/PSTN is NIST's restricted authenticator and the
weakest option: SIM swap and number porting are outside your control. Recovery codes must be
single-use and stored hashed. A password change, MFA removal, new payout destination, or
impersonation start should require recent authentication plus a second factor.

```python
# Fixed: recovery code is shown once, stored as a hash, and consumed atomically
code = secrets.token_urlsafe(16)
await db.recovery_codes.insert(user_id, sha256(code), used=False)
# display code once; never log it or store plaintext

candidate = sha256(request.form["code"])
row = await db.recovery_codes.consume_if_unused(user_id, candidate)
if row is None: raise Unauthorized("invalid_recovery_code")
```

Why this works: database readers cannot immediately use the code, and a replay loses because
consumption is atomic. A support agent who bypasses this process is a second login endpoint;
audit it like one.

## Authorization models and impersonation

`A01:2025` · ASVS V8, V16 · CWE-639, CWE-862

- RBAC fits stable job functions: `billing_viewer`, `billing_admin`. Keep role-to-permission
  mappings small and reviewable.
- ABAC fits rules over attributes: region, data classification, employment status, time.
  Centralise the policy and log input attributes and decision.
- ReBAC fits relationships: document owner, project member, delegated caregiver. Store and
  query the relationship; do not encode every ownership edge as a role.

Start with RBAC when roles are stable. Add ABAC or ReBAC for a named need. Do not build a
policy language nobody can test or explain. Enforce object scope in the data query.

```python
# Vulnerable: authenticated user can read another tenant's object
return db.documents.get(request.args["id"])

# Fixed: actor and tenant scope are part of the query; missing and forbidden look identical
return db.documents.first(id=request.args["id"], tenant_id=actor.tenant_id,
                          readable_by=actor.id) or raise_not_found()
```

Impersonation is a privileged, time-bounded session mode, not a role toggle. Store operator
and effective subject separately; require a reason and step-up; show a persistent banner; do
not let the operator impersonate into further admin actions; log start, each sensitive action,
and end. An unlogged `userId = targetId` makes the audit trail lie.
