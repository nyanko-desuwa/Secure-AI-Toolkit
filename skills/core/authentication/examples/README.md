# Authentication Examples

These examples show common authentication failures and safer implementation patterns. Adapter calls such as `db`, `redis`, and `oauth` stand for project-specific, tested integrations. Public responses remain deliberately generic, while internal audit events retain enough context for investigation without recording credentials or tokens.

## 1. Uniform login errors

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V6 · CWE-204, CWE-208

### Vulnerable:

Different status codes and messages reveal whether an account exists. The missing-account branch also returns before an expensive password check, creating a timing oracle.

```typescript
const user = await users.findByEmail(req.body.email);

if (!user) {
  return res.status(404).json({ error: "account_not_found" });
}

if (!(await argon2.verify(user.passwordHash, req.body.password))) {
  return res.status(401).json({ error: "wrong_password" });
}

return establishSession(req, res, user.id);
```

### Fixed:

Normalize the identifier, verify against a valid dummy Argon2id hash when no account exists, and return the same public result for all authentication failures. Keep detailed reasons only in access-controlled audit records.

```typescript
const identifier = normalizeEmail(req.body.email);
const user = await users.findByEmail(identifier);
const candidateHash = user?.passwordHash ?? DUMMY_ARGON2ID_HASH;
const passwordValid = await argon2.verify(candidateHash, req.body.password);

if (!user || !passwordValid || user.disabled) {
  await audit.write("login_failed", {
    accountRef: auditAccountRef(identifier),
    reason: !user ? "unknown_account" : user.disabled ? "disabled" : "bad_password",
    sourceIp: req.ip,
  });
  return res.status(401).json({ error: "invalid_credentials" });
}

return establishSession(req, res, user.id);
```

The fixed path performs comparable password-hash work and exposes one status and message. `DUMMY_ARGON2ID_HASH` must be a valid hash generated for deployment, not a secret or a hash copied from a real account.

## 2. Distributed login throttling

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V6, V16 · CWE-307

### Vulnerable:

An in-process, IP-only counter resets on deployment and can be bypassed by distributing attempts across workers or source addresses.

```typescript
const attempts = new Map<string, number>();
const count = (attempts.get(req.ip) ?? 0) + 1;
attempts.set(req.ip, count);

if (count > 10) {
  return res.sendStatus(429);
}

return checkCredentials(req, res);
```

### Fixed:

Use a shared, atomic store and combine account, source, device, and global signals. Apply bounded delays or challenges without permanently locking a victim's account.

```typescript
const accountKey = hmacIndex(normalizeEmail(req.body.email));
const deviceKey = stableDeviceSignal(req);

const decision = await distributedLimiter.consume([
  { key: `acct:${accountKey}`, limit: 8, windowSeconds: 900 },
  { key: `ip:${req.ip}`, limit: 40, windowSeconds: 300 },
  { key: `device:${deviceKey}`, limit: 20, windowSeconds: 600 },
  { key: "login:global", limit: 20_000, windowSeconds: 60 },
]);

if (!decision.allowed) {
  await audit.write("login_throttled", {
    accountRef: accountKey,
    sourceIp: req.ip,
    retryAfterSeconds: decision.retryAfterSeconds,
  });
  res.setHeader("Retry-After", String(decision.retryAfterSeconds));
  return res.status(429).json({ error: "try_again_later" });
}

return checkCredentials(req, res);
```

The limiter must execute increments and expiry atomically in shared storage. Rate-limit keys should avoid storing raw account identifiers, and successful logins should not erase evidence needed to detect password spraying.

## 3. Password reset tokens

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V6 · CWE-640

### Vulnerable:

A predictable token is stored in plaintext, can be reused, and is exposed in logs.

```python
reset_token = str(user.id) + str(int(time.time()))
await db.password_resets.insert(
    user_id=user.id,
    token=reset_token,
    expires_at=now() + timedelta(days=1),
)
logger.info("password reset token=%s", reset_token)
mail_reset_link(user.email, f"https://app.example.test/reset?token={reset_token}")
```

### Fixed:

Generate a high-entropy token, store only its hash, set a short expiry, and consume it atomically. Return a uniform response whether the submitted email exists or not.

```python
import hashlib
import secrets
from datetime import timedelta

async def request_reset(email: str) -> None:
    user = await db.users.find_by_normalized_email(normalize_email(email))
    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("ascii")).digest()
        await db.password_resets.replace_active(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now() + timedelta(minutes=15),
        )
        await mailer.send_reset(user.email, raw_token)
    # The HTTP handler always returns the same accepted response.

async def complete_reset(raw_token: str, new_password: str) -> None:
    token_hash = hashlib.sha256(raw_token.encode("ascii")).digest()
    async with db.transaction():
        reset = await db.password_resets.consume_unexpired(token_hash, now())
        if reset is None:
            raise InvalidResetToken()
        await db.users.set_argon2id_password(reset.user_id, new_password)
        await db.sessions.revoke_all(reset.user_id)
        await db.refresh_tokens.revoke_all(reset.user_id)
```

`consume_unexpired` must be a single transactional operation so concurrent requests cannot redeem the same token twice. Do not place reset tokens in application logs, analytics, or referrer-bearing third-party pages.

## 4. Session cookie and identifier rotation

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V7 · CWE-384, CWE-614

### Vulnerable:

Authentication is attached to the pre-login session identifier, and the cookie can be read by scripts or sent over an unencrypted connection.

```javascript
req.session.userId = user.id;
res.cookie("sid", req.sessionID, {
  httpOnly: false,
  secure: false,
});
res.redirect("/account");
```

### Fixed:

Regenerate the server-side session after authentication and issue a host-only secure cookie. Enforce idle and absolute expiry in server state, not only in the browser.

```javascript
await new Promise((resolve, reject) => {
  req.session.regenerate((error) => (error ? reject(error) : resolve()));
});

req.session.userId = user.id;
req.session.authenticatedAt = Date.now();
req.session.lastSeenAt = Date.now();
req.session.absoluteExpiresAt = Date.now() + 8 * 60 * 60 * 1000;

res.cookie("__Host-sid", req.sessionID, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
  maxAge: 30 * 60 * 1000,
});
res.redirect("/account");
```

The server must reject expired sessions and revoke them on logout, password reset, account disablement, and MFA changes. `SameSite=Lax` is defense in depth; state-changing requests still need an appropriate CSRF defense.

## 5. JWT verification

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V9, V11 · CWE-347

### Vulnerable:

Decoding is not verification. This code trusts attacker-controlled claims without proving who signed the token.

```javascript
const payload = jwt.decode(req.headers.authorization.slice(7));

if (payload.role === "admin") {
  return showAdministrationConsole(res);
}

return res.sendStatus(403);
```

### Fixed:

Use a trusted key source, pin the allowed algorithm, and validate issuer, audience, and time-based claims before authorization. Treat key-selection headers as untrusted input.

```javascript
const token = extractBearerToken(req);
const { payload, protectedHeader } = await jwtVerify(token, trustedJwks, {
  algorithms: ["RS256"],
  issuer: "https://id.example.test",
  audience: "administration-api",
  clockTolerance: 5,
  maxTokenAge: "10m",
});

if (protectedHeader.typ !== "at+jwt") {
  return res.sendStatus(401);
}
if (!payload.scope?.split(" ").includes("admin:read")) {
  return res.sendStatus(403);
}

return showAdministrationConsole(res);
```

Configure `trustedJwks` from an allowlisted issuer and reject unknown `kid` values; never fetch a key from an arbitrary token-supplied `jku` or `x5u`. Short-lived access tokens limit exposure, but immediate logout requires server-side revocation or session state.

## 6. OAuth2/OIDC callback

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V10 · CWE-352, CWE-601

### Vulnerable:

The callback does not bind the response to the initiating browser, accepts a caller-controlled redirect, and omits PKCE.

```typescript
app.get("/oauth/callback", async (req, res) => {
  const tokens = await oauth.exchangeCode(String(req.query.code));
  await loginFromIdToken(req, tokens.id_token);
  res.redirect(String(req.query.return_to ?? "/"));
});
```

### Fixed:

Store one-use transaction state server-side, compare `state`, exchange the code with the original PKCE verifier and exact registered redirect URI, and validate the OIDC ID token and nonce.

```typescript
app.get("/oauth/callback", async (req, res) => {
  const transaction = await oauthTransactions.consume(req.session.id);
  const receivedState = String(req.query.state ?? "");

  if (!transaction || !constantTimeEqual(receivedState, transaction.state)) {
    return res.status(401).json({ error: "invalid_oauth_response" });
  }

  const tokens = await oauth.exchangeAuthorizationCode({
    code: String(req.query.code ?? ""),
    codeVerifier: transaction.codeVerifier,
    redirectUri: REGISTERED_CALLBACK_URI,
  });

  const identity = await oidc.verifyIdToken(tokens.id_token, {
    issuer: TRUSTED_ISSUER,
    audience: OIDC_CLIENT_ID,
    nonce: transaction.nonce,
  });

  await regenerateAndLogin(req, identity.subject);
  return res.redirect(transaction.allowlistedDestination);
});
```

Generate `state`, `nonce`, and the PKCE verifier with a cryptographically secure random generator; use PKCE `S256`. Register and send an exact callback URI, and map post-login destinations to an allowlist rather than accepting arbitrary URLs.

## 7. MFA recovery codes

**Mapping:** OWASP Top 10 2025 A07: Authentication Failures · ASVS 5.0 V6 · CWE-308

### Vulnerable:

Recovery codes are stored in plaintext, remain valid after use, and are logged during verification.

```python
recovery_codes = ["sample-code-a", "sample-code-b"]
await db.users.update(user_id, recovery_codes=recovery_codes)

submitted = request.form["code"]
logger.info("MFA recovery attempt code=%s", submitted)
if submitted in user.recovery_codes:
    return create_authenticated_session(user.id)
raise Unauthorized()
```

### Fixed:

Generate independent high-entropy codes, display them once, store only keyed hashes, and atomically consume one code. Require a fully authenticated factor before generating a replacement set.

```python
import hashlib
import hmac
import secrets

RECOVERY_INDEX_KEY = load_key_from_secret_manager("mfa-recovery-index-key")

def recovery_digest(code: str) -> bytes:
    return hmac.new(
        RECOVERY_INDEX_KEY,
        code.encode("utf-8"),
        hashlib.sha256,
    ).digest()

async def replace_recovery_codes(user_id: str, recent_mfa: bool) -> list[str]:
    if not recent_mfa:
        raise StepUpRequired()
    raw_codes = [secrets.token_urlsafe(16) for _ in range(10)]
    await db.recovery_codes.replace_all(
        user_id,
        [recovery_digest(code) for code in raw_codes],
    )
    return raw_codes  # Render once over an authenticated TLS session; never log.

async def use_recovery_code(user_id: str, submitted: str) -> None:
    digest = recovery_digest(submitted)
    consumed = await db.recovery_codes.consume_if_unused(user_id, digest)
    if not consumed:
        raise Unauthorized("invalid_recovery_code")
    await audit.write("mfa_recovery_code_used", {"user_id": user_id})
```

`consume_if_unused` must be atomic to prevent replay races. After successful recovery, notify the account owner through an established channel, rotate the session identifier, and offer immediate revocation of remaining codes and sessions.
